import numpy as np
from typing import Any
from classes.pipeline import Stage

class CheckBlockConditionStage(Stage):
    """
    Класс этапа (stage) для pipeline. Проверяет условия и принимает решение о блокировке подозрительных ip-адресов.
    Решение принимается на основе данных из предыдущих этапов - высокая активность или отрицательная проверка из virustotal
    """

    def __init__(self):
        self.results={}

    def process(self, data:Any):
        """Операции по проверке условий блокировки, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Проверка условий для блокировки IP")
        print("="*70)

        # Проверяем условия и формируем список ip для блокировки
        data["ips_for_block"]=self.decide_blocking(data['suspicious_ips'],data['virustotal_ips'])

        # Выводим результат принятия решения
        self.print_results()

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Проверка условий для блокировки IP")
        print(f"Данные на конец этапа: {data}")
        print("="*70)
        return data

    def decide_blocking(self, suspicious_ips,virustotal_ips):
        """Принимаем решение о блокировке IP на основе входных данных"""
        
        for ip, info in suspicious_ips.items():
            # Проверяем условия для блокировки:
            # - всех с большим кол-вом запросов
            # - с отрицательной проверкой в VirusTotal
            vt_check = virustotal_ips.get(ip, False)
            
            if info.get('activity_threshold', False):
                print(f"IP: {ip} будет заблокирован из-за высокой активности (запросов = {info.get('total_requests', False)})")
                self.results[ip]="block_by_score"
            elif vt_check:
                print(f"IP: {ip} будет заблокирован из-за отрицательной проверки VirusTotal")
                self.results[ip]="block_by_virustotal"
            else:
                print(f"IP: {ip} не подходит для блокировки. Низкая активность = {info.get('total_requests', False)}, проверка VirusTotal = {vt_check}")

        return self.results

    def print_results(self):
        """Выводим результаты проверки о блокировке в читаемом виде"""
        print("\nСПИСОК IP И ПРИЧИНА ДЛЯ ПОСЛЕДУЮЩЕЙ БЛОКИРОВКИ:")
        
        for ip,value in self.results.items():
            print(f"{ip} {value}")
