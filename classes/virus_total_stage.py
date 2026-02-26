import os
import requests
import time
import random
from dotenv import load_dotenv
from typing import Any
from classes.pipeline import Stage

class VirusTotalStage(Stage):
    """
    Класс этапа (stage) для pipeline, производящий проверку подозрительных ip в сервисе VirusTotal
    """

    def __init__(self):
        # Загружаем .env файл
        load_dotenv()

        # Получаем из него ключ для virustotal
        api_key = os.getenv("API_KEY_VIRUSTOTAL")

        if not api_key:
            raise ValueError("API_KEY не установлен в env!")

        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}
        self.results = None
        self.sleep = 16

    def process(self, data:Any):
        """Операции по проверке ip в virustotal, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Обогащение данными из Virustotal")
        print("="*70)

        # Обогащаем данные по подозрительным ip из suricata данными из virustotal
        data["virustotal_ips"] = self.check_ips(set(data["suspicious_ips"]))

        # Вывод результата обогащения
        self.print_results()

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Обогащение данными из Virustotal")
        print(f"Данные на конец этапа: {data}")
        print("="*70)

        return data

    def check_ip(self, ip):
        """Проверяет один IP, возвращает True если подозрительный"""
        url = f"{self.base_url}/ip_addresses/{ip}"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            # Возвращаем True если есть вредоносные или подозрительные обнаружения
            return stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0
            
        except Exception as e:
            print(f"Ошибка при проверке {ip}: {e}")
            return None
    
    def check_ips(self, ip_list):
        """Проверяет список IP, возвращает словарь с результатами"""
        self.results = {}
        
        for i, ip in enumerate(ip_list):
            print(f"Проверка {i+1}/{len(ip_list)}: {ip}")
            self.results[ip] = self.check_ip(ip)
            
            # Задержка для соблюдения лимитов API
            if i < len(ip_list) - 1:
                time.sleep(self.sleep)
        
        return self.results
    
    def print_results(self):
        """Выводит результаты Virtustotal в читаемом виде"""
        print("\nРЕЗУЛЬТАТЫ ПРОВЕРКИ IP В VIRUSTOTAL:")
        
        for ip, is_suspicious in self.results.items():
            status = "ПОДОЗРИТЕЛЬНЫЙ" if is_suspicious else "БЕЗОПАСНЫЙ"
            print(f"{ip}: {status}")

    def get_suspicious_results(self):
        ips = [k for k, v in self.results.items() if v]
        return ips
    

class VirusTotalMockStage(VirusTotalStage):
    """
    Класс mock обращений к Virustotal, возвращая случайный результат проверки
    """
    def __init__(self, suspicious_probability=0.6):
        self.probability = suspicious_probability   # вероятность возврата подозрительного IP (по умолчанию 60%)
        self.results = None
        self.sleep = 1

    def check_ip(self, ip):
        """Возвращаем случайное значение результата проверки"""
        return random.random() < self.probability
  