"""Idempotent additive Alembic operations for legacy appliance schema adoption."""
from alembic import op as _op
from sqlalchemy import inspect, Column

class AdditiveOperations:
    def __getattr__(self, name):
        return getattr(_op, name)

    def create_table(self, name, *items, **kwargs):
        if not inspect(_op.get_bind()).has_table(name, schema=kwargs.get("schema")):
            return _op.create_table(name, *items, **kwargs)
        for column in items:
            if isinstance(column, Column):
                self.add_column(name, column, schema=kwargs.get("schema"))

    def add_column(self, table, column, **kwargs):
        columns = inspect(_op.get_bind()).get_columns(table, schema=kwargs.get("schema"))
        if column.name not in {c["name"] for c in columns}:
            return _op.add_column(table, column, **kwargs)

    def create_index(self, name, table, columns, **kwargs):
        indices = inspect(_op.get_bind()).get_indexes(table, schema=kwargs.get("schema"))
        if name not in {i["name"] for i in indices}:
            return _op.create_index(name, table, columns, **kwargs)

op = AdditiveOperations()
