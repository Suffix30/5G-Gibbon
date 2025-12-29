#!/usr/bin/env python3
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn, TimeElapsedColumn
from rich.console import Console
from typing import Optional
import logging
 
logger = logging.getLogger(__name__)

class ProgressTracker:
    def __init__(self):
        self.console = Console()
        self.progress = None
        self._task_ids = {}
    
    def create_progress(self, description="Working..."):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False
        )
        return self.progress
    
    def track(self, description: str, total: int = 100):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console
        )
        return _ProgressContext(self, description, total)
    
    def update(self, task_id: str, completed: int = 0, description: Optional[str] = None):
        if self.progress and task_id in self._task_ids:
            tid = self._task_ids[task_id]
            if description:
                self.progress.update(tid, completed=completed, description=description)
            else:
                self.progress.update(tid, completed=completed)


class _ProgressContext:
    def __init__(self, tracker: 'ProgressTracker', description: str, total: int):
        self.tracker = tracker
        self.description = description
        self.total = total
        self.task_id = description
    
    def __enter__(self) -> str:
        if self.tracker.progress:
            self.tracker.progress.start()
            tid = self.tracker.progress.add_task(self.description, total=self.total)
            self.tracker._task_ids[self.task_id] = tid
        return self.task_id
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self.tracker.progress:
            self.tracker.progress.stop()
        return False
    
    @staticmethod
    def track_operation(description, total, update_func):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
            console=Console()
        ) as progress:
            task = progress.add_task(description, total=total)
            
            result = None
            completed = 0
            
            try:
                for item in update_func():
                    completed += 1
                    progress.update(task, completed=completed)
                    yield item
                    result = item
            except KeyboardInterrupt:
                progress.update(task, description=f"[red]{description} (Cancelled)")
                raise
            finally:
                if result is not None:
                    progress.console.print(f"[dim]Last result: {type(result).__name__}[/dim]")
                progress.update(task, completed=total)

