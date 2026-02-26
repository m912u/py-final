import requests
import os
from dotenv import load_dotenv
from typing import Any,List
from classes.pipeline import Stage

class FirewallBanStage(Stage):
    """
    Класс этапа (stage) для pipeline, производящий блокировку ip-адресов. 
    Реализован абстрактный вызов API Firewall для блокировки списка подозрительных ip с предыдущего этапа
    """

    def __init__(self):
        self.results = {}
        
        # Загружаем .env файл
        load_dotenv()

        # Получаем из него ключ для virustotal
        api_key = os.getenv("API_KEY_FIREWALL")

        if not api_key:
            raise ValueError("API_KEY не установлен в env!")

        self.api_key = api_key
        self.base_url = "https://your-firewall-url.local/v2/"

    def process(self, data:Any):
        """Операции по блокировке ip, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Блокировка подозрительных ip с помощью API Firewall")
        print("="*70)

        data["block_result"]=self.ban(list(data['ips_for_block']))
        self.print_results()

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Блокировка подозрительных ip с помощью API Firewall")
        print(f"Данные на конец этапа: {data}")
        print("="*70)
        return data

    def ban(self, ip_list: List[str]) -> dict:
        """Блокировка списка IP через API"""
        self.results = {}
        
        for ip in ip_list:
            print(f"Блокировка {ip}...", end=" ")
            
            try:
                response = requests.post(
                    f"{self.base_url}/block",
                    headers={"API-Key": self.api_key},
                    json={"ip": ip, "action": "block"},
                    timeout=5
                )
                
                self.results[ip] = response.status_code == 200
                print("Заблокирован" if self.results[ip] else "Не заблокирован")
                
            except Exception as e:
                self.results[ip] = False
                print(f"Не заблокирован ({e})")
                    
        return self.results
        
    def print_results(self):
        """Выводит результаты блокировки в читаемом виде"""
        print("\nСПИСОК IP И РЕЗУЛЬТАТ ИХ БЛОКИРОВКИ:")
        
        for ip,result in self.results.items():
            print(f"{ip} {'заблокирован' if result else 'Не заблокирован'} ")

class FirewallBanMockStage(FirewallBanStage):
    """Класс mock обращения к API Firewall на блокировку ip"""
    def __init__(self, suspicious_probability=0.6):
        self.results = {}

    def ban(self, ip_list: List[str]) -> dict:
        """Блокировка списка IP через API"""
        self.results = {}
        
        for ip in ip_list:
            print(f"Блокировка {ip}...", end=" ")
            self.results[ip] = True
            print("Заблокирован")
        return self.results