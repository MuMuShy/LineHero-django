import logging

from dirtyfields import DirtyFieldsMixin
from django.core.serializers import serialize

logger = logging.getLogger(__name__)


class LogChangesMixin(DirtyFieldsMixin):
    def save(self, *args, **kwargs):
        changes = self._get_field_change_map()
        super().save(*args, **kwargs)
        if changes:
            logger.debug('Model changed: {}#{} {}'.format(
                self.__class__.__name__, self.pk, str(self)))
            for k, diff in changes.items():
                logger.debug('* {}: {} >>> {}'.format(
                    k, diff[0], diff[1]))

    def delete(self, using=None, keep_parents=False):
        serialized = serialize('json', [self], ensure_ascii=False)
        pk = self.pk
        result = super().delete(using, keep_parents)
        logger.debug('Model deleted: {}#{} {}'.format(
            self.__class__.__name__, pk, serialized))
        return result

    def _get_field_change_map(self):
        changes = {k: (v, getattr(self, k)) for k, v in
                   self.get_dirty_fields().items()}
        is_new = not self.pk  # not saved yet
        changes = {k: pair for k, pair in changes.items() if
                   pair[0] != pair[1] or is_new}
        return changes
