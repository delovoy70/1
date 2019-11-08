#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';
import argparse
import gzip
import re
import os
import datetime
import logging
import pandas as pd
from shutil import copyfile
from string import Template
import yaml
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

    def to_dict(self):
        return {
            'url': self.request.split()[1],
            'request_time': self.request_time,
            'count': self.request.split()[1],
            'time_sum': float(self.request_time),
            'time_max': float(self.request_time),
            'time_med': float(self.request_time),
        }


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

    pattern_file = r'nginx-access-ui.log-+\d{8}\.gzip|'
    files = os.listdir(log_dir)
    max_date = datetime.date(1, 1, 1)
    log_name = ''

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
        return {}
    return {
        'log_name': log_dir + '\\' + log_name,
        'log_date': max_date,
    }


def read_log(log_name):

    l_lexer = lexer(RULES)
    result = []

    with gzip.open(log_name) if log_name[-3:] == '.gz' else open(log_name) as f:
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
            if len(entry.request.split()) > 1:
                result.append(entry)

    return result


def process_data(log_data, report_size):
    pd_log_data = pd.DataFrame.from_records([ld.to_dict() for ld in log_data])
    pd_log_data1 = pd_log_data.groupby('url').agg({'count': 'count'}) \
        .join(pd_log_data.groupby('url').agg({'time_sum': 'sum'})) \
        .join(pd_log_data.groupby('url').agg({'time_max': 'max'})) \
        .join(pd_log_data.groupby('url').agg({'time_med': 'median'}))

    total_count = pd_log_data1['count'].sum()
    total_time = pd_log_data1['time_sum'].sum()

    pd_log_data1 = pd_log_data1.sort_values(by=['time_sum'], ascending=False).head(report_size)

    count_perc = []
    time_perc = []
    time_avg = []
    time_sum = []
    time_med = []

    for index, row in pd_log_data1.iterrows():
        count_perc.append(round(row['count'] * 100 / total_count, 3))
        time_perc.append(round(row['time_sum'] * 100 / total_time, 3))
        time_avg.append(round(row['time_sum'] / row['count'], 3))
        time_sum.append(round(row['time_sum'], 3))
        time_med.append(round(row['time_med'], 3))

    pd_log_data1['count_perc'] = count_perc
    pd_log_data1['time_perc'] = time_perc
    pd_log_data1['time_avg'] = time_avg
    pd_log_data1['time_sum'] = time_sum
    pd_log_data1['time_med'] = time_med

    return pd_log_data1


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='optional path to config file .yml', default='')
    args = parser.parse_args()
    if args.config:
        try:
            with open(args.config, 'r') as f:
                file_conf = yaml.load(f, Loader=yaml.Loader)
                log_dir = file_conf['LOG_DIR'] if 'LOG_DIR' in file_conf.keys() else config['LOG_DIR']
                report_size = file_conf['REPORT_SIZE'] if 'REPORT_SIZE' in file_conf.keys() else config['REPORT_SIZE']
                report_dir = file_conf['REPORT_DIR'] if 'REPORT_DIR' in file_conf.keys() else config['REPORT_DIR']
        except:
            sys.exit()
    else:
        log_dir = config['LOG_DIR']
        report_size = config['REPORT_SIZE']
        report_dir = config['REPORT_DIR']

    log_params = find_newest_log(log_dir)
    log_date = log_params['log_date']
    report_name = 'report-' + log_date.strftime('%Y.%m.%d') + '.html'

    files = os.listdir(report_dir)
    if report_name in files:
        print('Report ' + report_name + ' already exist. Abort proceeding logs')
        sys.exit()
    log_name = log_params['log_name']

    log_data = read_log(log_name)
    processed_data = process_data(log_data, report_size)
    processed_data = processed_data.reset_index().to_json(orient='records', index=True)

    report_path = '/'.join([report_dir, report_name])
    copyfile('report.html', report_path)

    with open(report_path) as f:
        s = f.read()

    repl_map = {
        'table_json': processed_data,
    }

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(Template(s).safe_substitute(repl_map))


if __name__ == "__main__":
    main()
