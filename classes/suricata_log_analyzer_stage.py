import os
import pandas as pd
import gc
from typing import Any
from classes.pipeline import Stage

class SuricataLogAnalyzerStage(Stage):
    """
    Класс этапа (stage) для pipeline, производящий загрузку и анализ логов Suricata в формате JSON.
    Позволяет загружать данные, анализировать активность IP-адресов и выявлять подозрительные IP.
    """
    
    def __init__(self,filename:str = "logs.json"):
        self.df = None
        self.filename = filename

    def process(self, data:Any):
        """Операции для загрузки, нормализации и анализу логов, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Загрузка данных из файла логов Suricata")
        print("="*70)
        
        # Загружаем логи из файла
        self.load_data()

        # Нормализуем загруженные логи
        self.normalize_data()

        # Вывод результаты загруки и нормализации
        self.print_info()

        # Анализ подозрительных IP
        data = {"suspicious_ips": self.get_suspicious_ips()}

        # Поскольку логи м.б. большие - освободим память перед переходом к следующим этапам
        self.clear_data()

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Загрузка данных из файла логов Suricata")
        print(f"Данные на конец этапа: {data}")
        print("="*70)

        return data

    def load_data(self):
        """Загрузка данных из лог-файла Suricata"""
        
        try:
            # Проверяем существование файла
            if not os.path.exists(self.filename):
                print(f"Файл {self.filename} не найден!")
                return None
            
            print("Загружаем данные...")
            
            # Загружаем JSON в DataFrame
            with open(self.filename, 'r', encoding='utf-8') as f:
                self.df = pd.read_json(self.filename)
            
            print(f"Загружено {len(self.df)} записей")

            # Проверяем наличие колонки src_ip
            if 'src_ip' not in self.df.columns:
                print("В файле нет колонки 'src_ip'!")
                return None
            
            return self.df
            
        except Exception as e:
            print(f"ОШИБКА при загрузке данных: {e}")
            return None
    
    def normalize_data(self):
        """Нормализацая загруженных данных"""
        print(f"Записей до нормализации: {len(self.df)}")
        
        # Удаляем дубликаты по полю flow_id
        self.df = self.df.drop_duplicates(subset=['flow_id'], keep='first')

        print(f"Записей после нормализации: {len(self.df)}")
        return self.df

    def clear_data(self):
        """Очистка памяти и запуск garbage collector"""
        self.df = None
        gc.collect()
        print("Очистка памяти завершена")

    def get_ip_statistics(self):
        """Возвращает кол-во запросов для каждого IP-адреса"""
        if self.df is None:
            print("Данные не загружены. Сначала вызовите load_data()")
            return None
            
        return self.df['src_ip'].value_counts()
    
    def get_alert_ips(self):
        """Получение IP-адресов, связанных с событиями типа alert"""
        if self.df is None:
            print("Данные не загружены. Сначала вызовите load_data()")
            return {}
        
        return self.df[self.df['event_type'] == 'alert']['src_ip'].value_counts().to_dict()
    
    def get_suspicious_ips(self, activity_multiplier=2):
        """Поиск подозрительных IP на основе активности выше среднего и\или наличия alert-событий"""
        if self.df is None:
            print("Данные не загружены. Сначала вызовите load_data()")
            return {}
        
        ip_stats = self.get_ip_statistics()                 # кол-во запросов для каждого ip
        alert_ips = self.get_alert_ips()                    # ip с алертами
        mean_requests = ip_stats.mean()                     # среднее кол-во запросов для ip
        threshold = mean_requests * activity_multiplier     # считаем порог по кол-ву запросов для ip (в activity_multiplier раз выше среднего)
        
        suspicious_ips = {}
        
        print("\nАНАЛИЗ ПОДОЗРИТЕЛЬНЫХ IP-АДРЕСОВ:")
        # Обходим все ip, получаем для каждого общее кол-во запросов и кол-во алертов
        for ip, total_count in ip_stats.items():
            alert_count = alert_ips.get(ip, 0)
            
            # если общее кол-во запросов превышает порог или есть алерты, то ip подозрительный
            if total_count > threshold or alert_count > 0:
                suspicious_ips[ip] = {
                    'total_requests': total_count,
                    'alert_requests': alert_count,
                    'activity_threshold': total_count > threshold,
                    'has_alerts': alert_count > 0
                }
        
        # Вывод результата поиска
        if suspicious_ips:
            print("\nIP адрес             Всего  Alerts  Порог")
            print("-" * 50)
                
            for ip, info in suspicious_ips.items():
                print(f"{ip:<20} {info['total_requests']:<8} "
                    f"{info['alert_requests']:<8} "
                    f"{'Да' if info['activity_threshold'] else 'Нет':<8} "
                    )

        else:
            print("\nПодозрительных IP не найдено")
        
        return suspicious_ips
    
    def print_info(self):
        """Вывод общей информации о загруженных данных"""
        if self.df is None:
            print("Данные не загружены")
            return
        
        print("\nИНФОРМАЦИЯ О ЗАГРУЖЕННЫХ ДАННЫХ:")
        print(f"Файл: {self.filename}")
        print(f"Всего записей: {len(self.df)}")
        print(f"Уникальных IP: {self.df['src_ip'].nunique()}")
        print(f"Распределение типов событий (event_type): {self.df['event_type'].value_counts().to_dict()}")
        print(f"Колонки в данных: {list(self.df.columns)}")

        if 'alert' in self.df['event_type'].values:
            print(f"Всего alert-событий: {len(self.df[self.df['event_type'] == 'alert'])}")