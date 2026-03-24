from transliterate import translit
from transliterate.base import TranslitLanguagePack, registry
from config import Config
import mysql.connector
import datetime as dt
from symspellpy import SymSpell, Verbosity
import pickle
import glob

PICKLE_PATH = 'symspell_dict_%s_words.pkl'
cfg = Config.get_db_config()

def is_russian(word: str) -> bool:
    return all('а' <= ch <= 'я' or ch == 'ё' for ch in word.lower())

_symspell = None

def init_symspell():
    global _symspell
    if _symspell is not None:
        return

    instance = SymSpell(max_dictionary_edit_distance=2, prefix_length=7)
    existing = glob.glob('symspell_dict_*_words.pkl')

    if existing:
        start = dt.datetime.now()
        with open(existing[0], 'rb') as f:
            instance = pickle.load(f)
        print(f"Словарь загружен из кэша: {instance.word_count} слов, время - {dt.datetime.now() - start}")
    else:
        start = dt.datetime.now()
        with open('ru_dict_480k_words.txt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2 and is_russian(parts[0]):
                    try:
                        instance.create_dictionary_entry(parts[0], int(parts[1]))
                    except ValueError:
                        continue
        with open(PICKLE_PATH % instance.word_count, 'wb') as f:
            pickle.dump(instance, f)
        print(f"Словарь построен и сохранён: {instance.word_count} слов, время - {dt.datetime.now() - start}")

    _symspell = instance

def get_symspell() -> SymSpell:
    if _symspell is None:
        raise RuntimeError("SymSpell не инициализирован. Вызови init_symspell() при старте.")
    return _symspell


# модуль, отвечающий за продвинутый поиск
# принцип поиска:
#
# 1. поиск по непосредственной строке в базе данных
# 2. поиск через транслитерацию строки
# 3. поиск через перевод раскладки (eng <-> rus)
# 4  попытка поиска опечаток
# 5. выборка по триграммам -> DL точно ранжирует
# 6. поиск по дамерау-левенштейну во всей БД

def advanced_search(search_string: str) -> list:
    start = dt.datetime.now()
    if not search_string:
        return []

    conn = mysql.connector.connect(**cfg)
    cursor = conn.cursor()
    try:

         # прямой поиск
        result = search_by_string(cursor, search_string)
        if result:
            finish = dt.datetime.now()
            print(f"Результат поиска по строке: {result}, время работы функции - {finish - start}")
            return result

        # транслитерация
        transliterated = translit(search_string, 'ru')
        print(f"Транслит строки \"{search_string}\" - \"{transliterated}\"")
        if transliterated != search_string:
            result = search_by_string(cursor, transliterated)
            if result:
                finish = dt.datetime.now()
                print(f"Результат поиска с помощью транслитерации: {result}, время работы функции - {finish - start}")
                return result
            
        # обратная транслитерация
        reverse_transliterated = translit(search_string, 'ru', reversed=True)
        print(f"Обратный транслит строки \"{search_string}\" - \"{reverse_transliterated}\"")
        if reverse_transliterated != search_string:
            result = search_by_string(cursor, reverse_transliterated)
            if result:
                finish = dt.datetime.now()
                print(f"Результат поиска с помощью транслитерации: {result}, время работы функции - {finish - start}")
                return result

         # раскладка
        registry.register(FromEngToRusLayoutPack)
        switched = translit(search_string, 'my')
        print(f"Переключение раскладки строки \"{search_string}\" - \"{switched}\"")
        if switched != search_string and switched != transliterated:
            result = search_by_string(cursor, switched)
            if result:
                finish = dt.datetime.now()
                print(f"Результат поиска с помощью смены раскладки: {result}, время работы функции - {finish - start}")
                return result
            
        search_variants = {search_string, transliterated, switched, reverse_transliterated}

        # опечатки
        spellcheck_candidates = get_symspell().lookup(search_string, Verbosity.CLOSEST, max_edit_distance=2)
        corrected_terms = {candidate.term for candidate in spellcheck_candidates}
        print(f"Symspell предложил: {corrected_terms}")
        for term in corrected_terms:
            if term not in search_variants:   # не повторяем уже проверенные
                result = search_by_string(cursor, term)
                if result:
                    finish = dt.datetime.now()
                    print(f"Найдено через symspell ({term}): {result}, время - {finish - start}")
                    return result
        search_variants.update(corrected_terms)
        
        # триграммы дают кандидатов -> DL точно ранжирует
        # пробуем оригинал, транслит (в т.ч обратный) и раскладку как источники кандидатов
        candidates = []
        for variant in search_variants:
            candidates += search_by_trigrams(cursor, variant)

        # убираем дубликаты по product_id
        seen = set()
        unique_candidates = []
        for row in candidates:
            if row[0] not in seen:
                seen.add(row[0])
                unique_candidates.append(row)

        if unique_candidates:
            print(f"Кандидаты из триграмм: {unique_candidates}")
            # прогоняем кандидатов через DL
            result = rank_by_dl(search_string, search_variants, unique_candidates)
            if result:
                finish = dt.datetime.now()
                print(f"Результат после DL: {result}, время работы функции - {finish - start}")
                return result
        
        # Дамерау-Левенштейн по всей базе, если не найдено ничего
        result = search_by_dl(cursor, search_string)
        if result:
            finish = dt.datetime.now()
            print(f"Результат поиска по DL: {result}, время работы функции - {finish - start}")
            return result
        
        finish = dt.datetime.now()
        print(f"Функция ничего не вернула, время работы - {finish - start}")
        return []

    except mysql.connector.Error as err:
        print(f"Во время поиска по строке \"{search_string}\" произошла ошибка базы данных {err}")
        return []
    
    finally:
        cursor.close()
        conn.close()

def search_by_trigrams(cursor, search_string: str) -> list:
    trigrams = make_trigrams(search_string.lower())
    if not trigrams:
        return []

    # минимальное число совпавших триграмм — 30% от общего числа
    min_matches = max(1, int(len(trigrams) * 0.3))

    placeholders = ','.join(['%s'] * len(trigrams)) #создаётся строка вида '%s, %s, %s', вместо %s будут подставляться триграммы
    cursor.execute(f"""
        SELECT p.product_id, p.product_name, COUNT(*) AS matched
        FROM products p
        JOIN product_trigrams pt ON pt.product_id = p.product_id
        WHERE pt.trigram IN ({placeholders})
        GROUP BY p.product_id, p.product_name
        HAVING matched >= %s
        ORDER BY matched DESC
    """, (*trigrams, min_matches))

    return cursor.fetchall()

def search_by_string(cursor, search_string: str) -> list:
    cursor.execute(
        "SELECT product_id, product_name FROM products WHERE product_name LIKE %s",
        (f"%{search_string}%",)
    )
    return cursor.fetchall()

def search_by_dl(cursor, search_string: str) -> list:
    query_len = len(search_string)
    threshold = get_threshold(query_len)

    # Загружаем все записи, потому что ищем вхождение слова внутри названия
    cursor.execute("SELECT product_id, product_name FROM products")
    candidates = cursor.fetchall()

    matches = []
    for product_id, product_name in candidates:
        # Разбиваем название на отдельные слова и проверяем каждое
        words = product_name.lower().split()
        best_distance = min(
            damerau_levenshtein(search_string.lower(), word)
            for word in words
        )
        if best_distance <= threshold:
            matches.append((product_id, product_name, best_distance))

    return sorted(matches, key=lambda x: x[2])

def rank_by_dl(search_string: str, search_variants: set, candidates: list) -> list:
    """
    search_variants — все варианты запроса: оригинал + транслит + symspell и т.д.
    Для каждого кандидата берём минимальную дистанцию по всем вариантам.
    """
    # порог считаем по самому длинному варианту (он обычно ближе к реальному слову)
    threshold = get_threshold(max(len(v) for v in search_variants))
    matches = []

    for row in candidates:
        product_id, product_name = row[0], row[1]
        words = product_name.lower().split()

        # дистанция по оригинальному запросу
        original_best = min(
            damerau_levenshtein(search_string.lower(), word)
            for word in words)
        
        # дистанция по всем вариантам (включая symspell)
        overall_best = min(
            damerau_levenshtein(variant.lower(), word)
                for variant in search_variants
                for word in words)
        
        if overall_best <= threshold:
                # via_original=1 означает "найдено через symspell" → идёт первым
                via_original = 1 if original_best == overall_best else 0
                matches.append((product_id, product_name, overall_best, via_original))

    return sorted(matches, key=lambda x: (x[2], x[3]))

def make_trigrams(text: str) -> list[str]:
    padded = f"  {text}  "
    trigram = [padded[i:i+3] for i in range(len(padded) - 2)]
    print(f"Триграмма слова \"{text}\" - {trigram}")
    return trigram

class FromEngToRusLayoutPack(TranslitLanguagePack):
    language_code = 'my'
    language_name = 'From English To Russian Layout'
    mapping = (
        "~`QqWwEeRrTtYyUuIiOoPp{[}]AaSsDdFfGgHhJjKkLl:;\"'ZzXxCcVvBbNnMm<,>.",
        "ЁёЙйЦцУуКкЕеНнГгШшЩщЗзХхЪъФфЫыВвАаПпРрОоЛлДдЖжЭэЯяЧчСсМмИиТтЬьБбЮю"
    )

def damerau_levenshtein(source: str, target: str) -> int:
    source_len = len(source)
    target_len = len(target)

    # Матрица стоимостей размером (source_len+1) × (target_len+1).
    # Строка i соответствует первым i символам source,
    # столбец j — первым j символам target.
    # costs[i][j] = минимальная стоимость превращения
    #               source[:i] в target[:j].
    #
    # Нулевая строка: превратить пустую строку в target[:j] = j вставок.
    # Нулевой столбец: превратить source[:i] в пустую строку = i удалений.
    costs = [
        [j if i == 0 else i if j == 0 else 0
         for j in range(target_len + 1)]
        for i in range(source_len + 1)
    ]

    for i in range(1, source_len + 1):
        for j in range(1, target_len + 1):
            # Символы совпадают — операция не нужна, берём стоимость как есть.
            # Не совпадают — замена стоит 1.
            substitution_cost = 0 if source[i-1] == target[j-1] else 1

            costs[i][j] = min(
                costs[i-1][j] + 1,                    # удаление из source
                costs[i][j-1] + 1,                    # вставка в source
                costs[i-1][j-1] + substitution_cost   # замена / совпадение
            )

            # Транспозиция: два соседних символа поменялись местами (ab → ba).
            # Проверяем, что source[i-1] == target[j-2] и source[i-2] == target[j-1].
            # Если да — стоимость равна costs до этих двух символов + 1.
            two_chars_swapped = (
                i > 1 and j > 1
                and source[i-1] == target[j-2]
                and source[i-2] == target[j-1]
            )
            if two_chars_swapped:
                costs[i][j] = min(costs[i][j], costs[i-2][j-2] + 1)

    return costs[source_len][target_len]

def get_threshold(length: int) -> int:
    if length <= 3:
        return 0
    if length <= 5:
        return 1
    return 2