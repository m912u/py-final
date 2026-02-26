import json
from classes.pipeline import Stage
from typing import Any

class IPReportStage(Stage):
    """
    Класс этапа (stage) для pipeline, формирующий итоговый отчет. 
    Соединяет данные из разных этапов по ip-адресу клиента, формирует итоговый json и сохраняет в файл
    """
    
    def __init__(self,filename: str = 'report.json'):
        self.named_dicts_for_report = {}
        self.filename = filename
        self.results = {}

    def process(self, data:Any):
        """Операции для формирования отчета и сохранению его в файл, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Формирование отчета")
        print("="*70)

        # Указываем перечень этапов, по которым будет сформирован отчет
        self.dicts_for_report=[
            "suspicious_ips",
            "virustotal_ips",
            "ips_for_block",
            "block_result"
        ]

        # Формируем отчет
        self.get_report(data)

        # Выводим отчет в консоль
        self.print_results()

        # Сохраняем отчет в файл
        data['report_file_save']=self.to_json()

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Формирование отчета")
        print(f"Данные на конец этапа: {data}")
        print("="*70)
        return data


    def get_report(self, data):
        """Формируем отчет - соединяем данные с разных этапов по ключу (ip)"""
        self.results = {}

        # Обходим все этапы в данных для отчета
        for dict_name, ip_dict in data.items():
            # Проверяем, входит этап в перечень этапов, по которым нужно сформировать отчет
            if dict_name not in self.dicts_for_report:
                continue
            # Если входит - соединяем данные этапа с общим отчетом по ip
            for ip, data in ip_dict.items():
                if ip not in self.results:
                    self.results[ip] = {}
                self.results[ip][dict_name] = data
        
        return self.results
    
    def to_json(self):
        """Сохраняем отчет в JSON"""
        if not self.results:
            self.get_report()
        
        json_str = json.dumps(self.results, indent=2, ensure_ascii=False, default=bool)
        
        try:
            with open(self.filename, 'w', encoding='utf-8') as f:
                f.write(json_str)
            print(f"Отчет успешно сохранен в файл {self.filename}")

        except Exception as e:
            print(f"ОШИБКА при записи отчета в файл: {e}")
            return False
        
        return True


    def print_results(self):
        """Вывод отчета в консоль в человекочитаемом виде"""
        print("Результат отчета:")
        for ip, data in self.results.items():
            print(f"\n{ip}:")
            for dict_name, dict_data in data.items():
                print(f"  {dict_name}: {dict_data}")