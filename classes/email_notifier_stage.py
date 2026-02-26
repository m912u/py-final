import os
import smtplib
from typing import Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv
from classes.pipeline import Stage

class EmailNotifierStage(Stage):
    """
    Класс этапа (stage) для pipeline. Производит отправку email уведомлений о заблокированных IP адресах
    """
    
    def __init__(self,email_to:str = "admin@example.com"):
        # Загружаем .env файл
        load_dotenv()
        
        # Получаем настройки из .env
        self.email = os.getenv("EMAIL_MAIL")
        self.password = os.getenv("EMAIL_PASSWORD")
        self.smtp_server = os.getenv("EMAIL_SMTP_SERVER")
        self.smtp_port = int(os.getenv("EMAIL_SMTP_PORT", "587"))

        if not all([self.email, self.password, self.smtp_server]):
            raise ValueError("SMTP не настроен в env!")
        
        self.email_to = email_to
    
    def process(self, data:Any):
        """Операции по отправке уведомлений, выполняемые в рамках этапа pipeline"""
        print("\n" + "="*70)
        print("НАЧАЛО ЭТАПА")
        print("Отправка почтовых оповещений о блокировке")
        print("="*70)

        body=self._create_message_body(
                data['block_result']
            )

        print ("Тело отправляемого сообщения:")
        print (body)

        result = self.send_email(
            to=self.email_to,
            subject=f"Блокировка IP - {datetime.now().strftime('%d.%m.%Y %H:%M')}",
            body=body
        )

        data['email_send_result']=result

        print("\n" + "="*70)
        print("КОНЕЦ ЭТАПА")
        print("Отправка почтовых оповещений о блокировкеn")
        print(f"Данные на конец этапа: {data}")
        print("="*70)
        return data

    def send_email(self, to: str, subject: str, body: str) -> bool:
        """Отправка email через SMTP"""
        try:
            # Создаем сообщение
            msg = MIMEMultipart()
            msg['From'] = self.email
            msg['To'] = to
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Отправляем
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email, self.password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Ошибка отправки: {e}")
            return False
    
    def _create_message_body(self, blocked_ips: list) -> str:
        """Создание текста письма"""
        if not blocked_ips:
            return "Нет заблокированных IP адресов"
        
        ip_list_str = ''
        for ip,result in blocked_ips.items():
            ip_list_str = ip_list_str+ f"\n{ip} {'заблокирован' if result else 'Не заблокирован'} "
        
        return f"""
УВЕДОМЛЕНИЕ О БЛОКИРОВКЕ IP

Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
IP адресов для блокировки: {len(blocked_ips)} 

Результаты блокировки:
{ip_list_str}
        """