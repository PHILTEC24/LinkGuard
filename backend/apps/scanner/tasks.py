from celery import shared_task
from .models import Scan
from .services import run_scan


@shared_task(bind=True, max_retries=2, default_retry_delay=5)
def execute_scan_task(self, scan_id: str):
    try:
        scan = Scan.objects.get(id=scan_id)
        return run_scan(scan).id
    except Scan.DoesNotExist:
        return None
    except Exception as exc:
        raise self.retry(exc=exc)

