# service-activity-monitor


[![Python Versions](https://img.shields.io/badge/Tested%20against%20Python-3.6%20to%203.12-green?logo=python&style=flat-square)](https://www.python.org/downloads/)



Tooling for monitoring processes activity inside a docker container. Depends on python and the well supported `psutil` package. 

Monitors:
  - child process cpu usage
  - child process disk usage
  - overall container network usage
  - jupyter kernel activity

Exposes Prometheus metrics regarding:
  - total outgoing network usage
  - total incoming network usage

# Quick-ish start

## Step 1

Inside your `Dockerfile` add the following. Please replace the `TARGET_VERSION` and adjust all `BUSY_THRESHOLD` for your application.

```Dockerfile
ARG ACTIVITY_MONITOR_VERSION=TARGET_VERSION

# Detection thresholds for application
ENV ACTIVITY_MONITOR_BUSY_THRESHOLD_CPU_PERCENT=1000
ENV ACTIVITY_MONITOR_BUSY_THRESHOLD_DISK_READ_BPS=1099511627776
ENV ACTIVITY_MONITOR_BUSY_THRESHOLD_DISK_WRITE_BPS=1099511627776
ENV ACTIVITY_MONITOR_BUSY_THRESHOLD_NETWORK_RECEIVED_BPS=1099511627776
ENV ACTIVITY_MONITOR_BUSY_THRESHOLD_NETWORK_SENT_BPS=1099511627776

# install service activity monitor
RUN apt-get update && \
  apt-get install -y curl && \
  # install using curl
  curl -sSL https://raw.githubusercontent.com/ITISFoundation/service-activity-monitor/main/scripts/install.sh | \
  bash -s -- ${ACTIVITY_MONITOR_VERSION} && \
  # cleanup and remove curl
  apt-get purge -y --auto-remove curl && \
  rm -rf /var/lib/apt/lists/*
```

## Step 2

Inside your boot script before starting your application start something similar to 

```bash
python /usr/local/bin/service-monitor/activity_monitor.py &
```

In most cases something similar to the below will do the trick (don't forget to replace `USER`).

```bash
exec gosu "$USER" python /usr/local/bin/service-monitor/activity_monitor.py &
```

## Step 3

Inside you image's label something similar to this should end up: 

```yaml
...
services:
  ...
  YOUR_SERVICE:
    ...
    build:
      labels:
        ...
        simcore.service.callbacks-mapping: '{"inactivity": {"service": "container",
          "command": ["python", "/usr/local/bin/service-monitor/activity.py"], "timeout":
          1.0}}'
```
Note if your service defines it's own compose spec. `container` must be replaced with the name of the service where these are installed.

In most cases you will easily configure this by adding the following to your `.osparc/service-name/runtime.yaml` file:

```yaml
...
callbacks-mapping:
  inactivity:
    service: container
    command: ["python", "/usr/local/bin/service-monitor/activity.py"]
    timeout: 1
```
# Available configuration options

##### The following flags disable the monitors. By default all the monitors are enabled.
- `ACTIVITY_MONITOR_DISABLE_JUPYTER_KERNEL_MONITOR` default=`False`: disables and does not configure the jupyter kernel monitor
- `ACTIVITY_MONITOR_DISABLE_CPU_USAGE_MONITOR` default=`False`: disables and does not configure the cpu usage monitor
- `ACTIVITY_MONITOR_DISABLE_DISK_USAGE_MONITOR` default=`False`: disables and does not configure the disk usage monitor
- `ACTIVITY_MONITOR_DISABLE_NETWORK_USAGE_MONITOR` default=`False`: disables and does not configure the network usage monitor

##### All the following env vars are to be interpreted as follows: if the value is greater than (>) threshold, the corresponding manager will report busy.
- `ACTIVITY_MONITOR_BUSY_THRESHOLD_CPU_PERCENT` [percentage(%)], default=`1000`: used cpu usage monitor
- `ACTIVITY_MONITOR_BUSY_THRESHOLD_DISK_READ_BPS` [bytes], default=`1099511627776`: used by disk usage monitor
- `ACTIVITY_MONITOR_BUSY_THRESHOLD_DISK_WRITE_BPS` [bytes], default=`1099511627776`: used by disk usage monitor
- `ACTIVITY_MONITOR_BUSY_THRESHOLD_NETWORK_RECEIVED_BPS` [bytes], default=`1099511627776`: used by network usage monitor
- `ACTIVITY_MONITOR_BUSY_THRESHOLD_NETWORK_SENT_BPS` [bytes], default=`1099511627776`: used by network usage monitor

##### Other:
- `ACTIVITY_MONITOR_JUPYTER_NOTEBOOK_BASE_URL` [str] default=`http://localhost:8888`: endpoint where the jupyter notebook is exposed
- `ACTIVITY_MONITOR_JUPYTER_NOTEBOOK_KERNEL_CHECK_INTERVAL_S` [float] default=`5`: used by the jupyter kernel monitor to update it's metrics
- `ACTIVITY_MONITOR_MONITOR_INTERVAL_S` [float] default=`1`: all other monitors us this interval to update their metrics
- `ACTIVITY_MONITOR_LISTEN_PORT` [int] default=`19597`: port on which the http server will be exposed



# Exposed API


### `GET /activity`

Used by oSPARC top retrieve the status of the service if it's active or not

```json
{"seconds_inactive": 0}
```

```bash
curl http://localhost:19597/activity
```

### `GET /debug`

Used for debugging and not used by oSPARC

```json
{
  "kernel_monitor": {
    "is_busy": true
  }, 
  "cpu_usage": {
    "is_busy": false, 
    "total": 0
  }, 
  "disk_usage": {
    "is_busy": false,
    "total": {
      "bytes_read_per_second": 0,
      "bytes_write_per_second": 0
    }
  }, 
  "network_usage": {
    "is_busy": false, 
    "total": {
      "bytes_received_per_second": 345452, 
      "bytes_sent_per_second": 343809
    }
  }
}
```

```bash
curl http://localhost:19597/debug
```

### `GET /metrics`

Exposes Prometheus metrics relative to the running processes.

```
# HELP network_bytes_received_total Total number of bytes received across all network interfaces.
# TYPE network_bytes_received_total counter
network_bytes_received_total 23434790

# HELP network_bytes_sent_total Total number of bytes sent across all network interfaces.
# TYPE network_bytes_sent_total counter
network_bytes_sent_total 22893843
```

```bash
curl http://localhost:19597/metrics
```

---

# Releasing

To create a new release just add a new tag (in the format `vX.X.X`) to a commit and push it. The CI will take care of creating the release.

To tag the current git commit and trigger a release run:

```bash
make release tag=vX.X.X
```