#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';


from typing import List
from itertools import groupby
import gzip
import re
import os
import datetime
import logging
import sys

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}


# lexeme types
WSP, QUOTED_STRING, DATE, RAW, NO_DATA = range(5) # ENUM

RULES = [
    ('\s+', WSP),
    ('-|"-"', NO_DATA),
    ('"([^"]+)"', QUOTED_STRING),
    ('\[([^\]]+)\]', DATE),
    ('([^\s]+)', RAW),
    ]


class LogEntry(object):
    __slots__ = ('remote_addr', 'remote_user', 'http_x_real_ip', 'time_local', 'request', 'status',
              'body_bytes_sent', 'http_referer', 'http_user_agent', 'http_x_forwarded_for',
              'http_X_REQUEST_ID', 'http_X_RB_USER', 'request_time')


def lexer(rules):
    # предварительно компилируем регулярные выражения для ускорения работы
    prepared = [(re.compile(regexp), token_type) for regexp, token_type in rules]

    def lex(line):
        ll = len(line)  # длина строки лога - чтобы знать, когда остановиться
        i = 0  # текущая позиция анализатора
        while i < ll:
            for pattern, token_type in prepared:  # пробуем регулярные выражения по очереди
                match = pattern.match(line, i)  # проверяем соответствует ли регулярное выражение строке с позиции i
                if match is None:  # если нет - пробуем следующую регулярку
                    continue
                i = match.end()  # передвигаем позицию анализатора до индекса, соответствующего концу совпадения
                yield (match, token_type)  # возвращаем найденный токен
                break  # начинаем анализировать остаток строки с новым значением сдвига i
    return lex


def read_log(log_dir):

    pattern_file = r'nginx-access-ui.log-+\d{8}\.gzip|'
    files = os.listdir(log_dir)
    max_date = datetime.date(1, 1, 1)
    log_name = ''

    l_lexer = lexer(RULES)

    for i in files:
        if re.match(pattern_file, i.lower()) is not None:
            try:
                year = int(i[20:24])
                month = int(i[24:26])
                day = int(i[26:28])
                if datetime.date(year, month, day) > max_date:
                    max_date = datetime.date(year, month, day)
                    log_name = i
            except ValueError:
                """это не наш формат имени лога"""
                pass

    if max_date == datetime.date(1, 1, 1):
        return ''

    result = []
    with gzip.open(log_dir + '\\' + log_name) if log_name[-2:] == 'gz' else open(log_dir + '\\' + log_name) as f:
        a = 1
        for line in f:
            if type(line) == bytes:
                line = line.decode()
            try:
                tokens = l_lexer(line)
            except Exception:
                logging.exception("Error in line '%s'", line)
                continue  # пропускаем битые строки
            entry = LogEntry()
            field_idx = 0
            for re_match, token_type in tokens:
                if token_type == WSP:
                    continue  # пробелы игнорируем
                elif token_type == NO_DATA:
                    value = None  # NO_DATA заменяем на None
                elif token_type == RAW:
                    value = re_match.group(1)  # MatchObject.group(i) возвращает i-ую заключённую в круглые скобки группу
                elif token_type == QUOTED_STRING:
                    value = re_match.group(1)  # снимаем экранирование с заэкранированных кавычек
                elif token_type == DATE:
                    value = datetime.datetime.strptime(re_match.group(1)[:-6], "%d/%b/%Y:%H:%M:%S")  # парсим дату
                else:
                    raise SyntaxError("Unknown token", token_type, re_match)

                field_name = LogEntry.__slots__[field_idx]
                setattr(entry, field_name, value)
                field_idx += 1
            result.append(entry)
            if a == 1000:
                break
            a += 1

    return result


def main():

    log_data = read_log(config['LOG_DIR'])
    # log_data.sort(key= lambda x: x.request)

    # with open("123.sql", 'w') as f:
    #     f.write(",\n".join([x.to_sql() for x in log_data]))

    print(log_data)
    #
    # print('==============================================')
    #
    # for k, v in groupby(log_data, key=lambda x: x.request):
    #     print(k, list(v))

    # print(sum(float(c.request_time) for c in log_data))


if __name__ == "__main__":
    main()
