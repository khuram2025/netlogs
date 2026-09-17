"""Load staged modules in a separate process, then execute a test script."""
import importlib.util
import runpy
import sys
sys.path.insert(0, '/app')
for name, path in [('fastapi_app.core.event_time', '/tmp/logfix/core/event_time.py'),
                   ('fastapi_app.db.clickhouse', '/tmp/logfix/db/clickhouse.py'),
                   ('fastapi_app.services.nql_schema', '/tmp/logfix/services/nql_schema.py'),
                   ('fastapi_app.api.views', '/tmp/logfix/api/views.py'),
                   ('fastapi_app.services.correlation_engine', '/tmp/logfix/services/correlation_engine.py'),
                   ('fastapi_app.services.ioc_sweep', '/tmp/logfix/services/ioc_sweep.py'),
                   ('fastapi_app.services.ioc_sightings', '/tmp/logfix/services/ioc_sightings.py')]:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
script = sys.argv[1]
sys.argv = [script]
runpy.run_path(script, run_name='__main__')
