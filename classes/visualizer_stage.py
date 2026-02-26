import matplotlib.pyplot as plt
from typing import Any
from classes.pipeline import Stage

class VisualizerStage(Stage):
    """
    Класс этапа (stage) для pipeline, визуализирующий статистику запросов в разере ip-адресов
    """
    def __init__(self,filename: str = 'report.png'):
        self.top_ips = []
        self.filename = filename

    def process(self, data:Any):
        """Операции по формированию визуализации и сохранению в файл, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Формирование графиков и визуализации")
        print("="*70)

        # Формируем данные для графиков
        self.init_data(data["suspicious_ips"])

        # Запускаем визуализацию и сохранение в файл
        data['visualize_file_save']=self.plot()

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Формирование графиков и визуализации")
        print(f"Данные на конец этапа: {data}")
        print("="*70)
        return data

    def init_data(self,data):
        """Формирование сортированного списка ТОР5 ip для графика"""
        # Сортируем IP по total_requests и берем TOP-5
        self.top_ips = sorted(
            [(ip, 
              info['total_requests'], 
              info['alert_requests']) 
             for ip, info in data.items()], 
            key=lambda x: x[1], reverse=True)[:5]

    def plot(self):
        """Отрисовывает график и сохраняет в файл"""
        if not self.top_ips:
            print("Нет данных для формирования графиков")
            return None
        
        fig, ax = plt.subplots(figsize=(14, 5))

        # Объявляем данные для визуализации
        ips = [x[0] for x in self.top_ips]
        total = [x[1] for x in self.top_ips]
        alerts = [x[2] for x in self.top_ips]

        # Настраиваем визуализацию
        x = range(len(ips))
        ax.bar(x, total, label='Total')
        ax.bar(x, alerts, label='Alerts', bottom=total)
        ax.set_xlabel('IP адреса')
        ax.set_ylabel('Количество запросов')
        ax.set_title('TOP-5 IP адресов')
        ax.set_xticks(x, ips)
        ax.legend()
        
        # Сохраняем визуализацию в файл
        try:
            plt.tight_layout()
            plt.savefig(self.filename)
            print(f"Визуализация успешно сохранена в файл {self.filename}")
            return True
        except Exception as e:
            print(f"ОШИБКА при формировании и записи визуализации в файл: {e}")
            return False

