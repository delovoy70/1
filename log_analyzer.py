#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import argparse
import collections
import datetime
import gzip
import json
import logging
import os
import re
import statistics
import sys
from shutil import copyfile
from string import Template
from typing import Dict

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "ERRORS_LEVEL": None,
    "LOG_FILE_NAME": "",
}

logging.basicConfig(
    format='[%(asctime)s] %(levelname).1s %(message)s',
    datefmt='%Y.%m.%d %H:%M:%S',
    level=logging.DEBUG,
    filename=None,
)

# lexeme types
WSP, QUOTED_STRING, DATE, RAW, NO_DATA = range(5)  # ENUM

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


def find_newest_log(log_dir):
    pattern_file = r'^nginx-access-ui\.log-(\d{8})(\.gz|\.log)'
    files = os.listdir(log_dir)
    max_date = datetime.date(1, 1, 1)
    log_name = ''
    EMPTY_DATE = datetime.date(1, 1, 1)

    for i in files:
        if re.match(pattern_file, i.lower()):
            try:
                log_date = datetime.datetime.strptime(i[20:28], '%Y%m%d').date()
                if log_date > max_date:
                    max_date = log_date
                    log_name = i
            except ValueError:
                """это не наш формат имени лога"""
                pass

    if max_date == EMPTY_DATE:
        return {}
    return {
        'log_name': os.path.join(log_dir, log_name),
        'log_date': max_date,
    }


def read_log(log_name, errors_level):
    l_lexer = lexer(RULES)

    with gzip.open(log_name) if log_name[-3:] == '.gz' else open(log_name) as f:

        lines, errors = 0, 0
        dict_data: Dict[str, list[float]] = collections.defaultdict(list)

        for line in f:

            lines += 1

            if type(line) == bytes:
                line = line.decode()
            try:
                tokens = l_lexer(line)
            except Exception:
                errors += 1
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
                    value = re_match.group(1)  # group(i) возвращает i-ую заключённую в круглые скобки группу
                elif token_type == QUOTED_STRING:
                    value = re_match.group(1)  # снимаем экранирование с заэкранированных кавычек
                elif token_type == DATE:
                    value = datetime.datetime.strptime(re_match.group(1)[:-6], "%d/%b/%Y:%H:%M:%S")  # парсим дату
                else:
                    raise SyntaxError("Unknown token", token_type, re_match)

                field_name = LogEntry.__slots__[field_idx]
                setattr(entry, field_name, value)
                field_idx += 1

            try:
                url = entry.request.split()[1]
            except:
                errors += 1
                continue

            dict_data[url].append(float(entry.request_time))

    if not errors_level is None:
        if 100 * errors / lines > errors_level:
            logging.WARNING(f'Too much errors: {errors} errors from {lines} rows')
            return []

    return dict_data


def process_data(dict_data, report_size):

    new_dict = {}
    arr = []
    for i in sorted(dict_data.items(), reverse=True, key=lambda x: sum(x[1])):
        arr.append(i[0])
    dict_data1 = new_dict.fromkeys(arr)

    for i in dict_data1.keys():
        dict_data1[i] = dict_data[i]

    data_for_report = []
    count, time = 0, 0
    for request_times in dict_data1.values():
        count += len(request_times)
        time += sum(request_times)

    for url, request_times in dict_data1.items():
        data_for_report.append({
            'url': url,
            'count': len(request_times),
            'count_perc': round(100 * len(request_times) / float(count), 3),
            'time_sum': round(sum(request_times), 3),
            'time_perc': round(100 * sum(request_times) / time, 3),
            'time_avg': round(statistics.mean(request_times), 3),
            'time_max': round(max(request_times), 3),
            "time_med": round(statistics.median(request_times), 3),
        })

    return data_for_report[:report_size]


def update_config(config_file):
    with open(config_file, 'r') as f:
        try:
            file_conf = json.load(f)
            config.update(file_conf)
        except:
            logging.WARNING(f'JSON in {config_file} is not a valid json dict')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='optional path to config file .json', default='')
    args = parser.parse_args()
    if args.config:
        if os.path.exists(args.config):
            update_config(args.config)
        else:
            logging.WARNING(f'file {args.config} does not exist')
            sys.exit()

    if config['LOG_FILE_NAME']:
        logger = logging.getLogger()
        logger.handlers.clear()
        logger.addHandler(logging.FileHandler(config['LOG_FILE_NAME']))

    logging.info('starting new parsing job')

    log_params = find_newest_log(config['LOG_DIR'])

    if not log_params:
        logging.info('There are no logs to proceed')
        sys.exit()

    log_date = log_params['log_date']
    report_name = 'report-' + log_date.strftime('%Y.%m.%d') + '.html'

    files = os.listdir(config['REPORT_DIR'])
    if report_name in files:
        logging.info('Report ' + report_name + ' already exist. Abort proceeding logs')
        sys.exit()

    log_name = log_params['log_name']

    log_data = read_log(log_name, config['ERRORS_LEVEL'])
    processed_data = process_data(log_data, config['REPORT_SIZE'])

    if not processed_data:
        logging.info('Nothing to put into the report')
        sys.exit()

    processed_data = json.dumps(processed_data)

    report_path = '/'.join([config['REPORT_DIR'], report_name])
    copyfile('report.html', report_path)

    with open(report_path) as f:
        s = f.read()

    repl_map = {
        'table_json': processed_data,
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(Template(s).safe_substitute(repl_map))


if __name__ == "__main__":
    try:
        main()
    except:
        logging.exception('Unexpected exception')
