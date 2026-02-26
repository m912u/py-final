from classes.pipeline import Pipeline
from classes.suricata_log_analyzer_stage import SuricataLogAnalyzerStage
from classes.virus_total_stage import VirusTotalMockStage,VirusTotalStage
from classes.check_block_condition_stage import CheckBlockConditionStage
from classes.firewall_ban_stage import FirewallBanMockStage,FirewallBanStage
from classes.email_notifier_stage import EmailNotifierStage
from classes.ip_report_stage import IPReportStage
from classes.visualizer_stage import VisualizerStage

def main():
    """
    Используется паттерн pipline для последовательного вызова этапов.
    В рамках этапов происходит получение, обогащение, обработка данных и передача их на следующий этап.
    """    
    pipeline = Pipeline([
        SuricataLogAnalyzerStage('events.json'),            # Чтение и анализ лога Suricata events.json
        VirusTotalMockStage(),                              # Обогащение логов из Virustotal (мок)
        #VirusTotalStage()                                  # Обогащение логов из Virustotal (реальное обращение)
        CheckBlockConditionStage(score_threshold=2),        # Проверка условий для блокировки подозрительных ip
        FirewallBanMockStage(),                             # Блокировка подозрительных ip на firewall (мок)
        #FirewallBanStage(),                                # Блокировка подозрительных ip на firewall (реальное обращение)
        EmailNotifierStage('admin_report@example.com'),     # Отправка почтовых оповещений на admin_report@example.local
        IPReportStage('ip_report.json'),                    # Формирование отчета и запись его в файл ip_report.json
        VisualizerStage('ip_report.png')                    # Формирование визуализации и запись в файл ip_report.png
    ])

    print("Pipeline стартует")
    result = pipeline.execute()
    print(f"Pipeline завершен с результатом: {result}")

if __name__ == "__main__":
    main()