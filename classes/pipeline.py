from typing import Any, List
from abc import ABC, abstractmethod

class Stage(ABC):
    """
    Абстрактный класс этапа (Stage) для pipeline
    """
    @abstractmethod
    def process(self, data: Any) -> Any:
        """Принимает данные, возвращает результат обработки"""
        pass

class Pipeline:
    """
    Класс реализует паттерн Pipline для последовательной обработки и обогащения данных несколькими этапами (Stage)
    """
    def __init__(self, stages: List[Stage]):
        self.stages = stages

    def execute(self, initial_data: Any = None) -> Any:
        """Запускает pipeline"""
        data = initial_data
        for stage in self.stages:
            data = stage.process(data)
        return data