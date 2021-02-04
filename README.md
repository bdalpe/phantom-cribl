# Phantom App for Cribl

## Introduction

The Splunk Phantom App for Cribl supports the ability to automatically replay or collect logs from defined LogStream collectors for analysis by your SIEM tools. 

Save SIEM license and infrastructure costs by forwarding logs as needed using just-in-time delivery.

Supports: Cribl 2.3+, Phantom 4.10+

## Installation

The app can be downloaded from the [Github Releases](https://github.com/bdalpe/phantom-cribl/releases) page in this repo.

### App Setup and Configuration

App configuration options:

| Setting | Description | Required |
| ------- | ----------- | :------: | 
| URL     | The URL of the Cribl LogStream master node. | ✅ |
| Worker Group | The name of the LogStream worker group. Leave blank if using a standalone instance. | ❌ |
| Username | Your username. Must have permissions to run collector jobs.<br>⚠️ OIDC authentication is not supported. | ✅ |
| Password | The password of the user. | ✅ |
| Verify SSL Server Cert? | True/False - Verify the SSL certificate signer is valid and trusted by Phantom. | ✅ |

## Supported Actions

### run collector job

1. Obtains collector configuration from the LogStream master node
2. Submit job to LogStream master node with configuration settings below
3. (If `waitForJobCompletion == True`) Checks the job status on a 5 second interval until `status == finished` is returned.

It is recommended that you use a [format block](https://docs.splunk.com/Documentation/Phantom/latest/Playbook/VPEFormatBlock) for building the filter and/or earliest/latest filters in this action.

Job configuration options:

| Parameter | Description | Accepted Value|  Required? |
| --------- | ----------- | -------- | :-------: |
| collector | The id of the Cribl LogStream collector. Must exist in the system. | string | ✅ |
| filter    | The JavaScript expression to use for filtering logs. | string | ✅ |
| earliest | The earliest time for event filtering. | Absolute `timeRangeType`: Epoch timestamp<br>Relative `timeRangeType`: [Time modifier](https://docs.cribl.io/v2.4/docs/collectors-schedule-run#relative) | ❌ |
| latest | The earliest time for event filtering. | Absolute `timeRangeType`: Epoch timestamp<br>Relative `timeRangeType`: [Time modifier](https://docs.cribl.io/v2.4/docs/collectors-schedule-run#relative)| ❌ |
| timeRangeType | Select the time mode for collector run. | `absolute` or `relative` | ✅ | 
| waitForJobCompletion | Should the playbook wait for the logs to finish collecting before continuing execution? | `True` or `False`| ✅ |

## Issues
If you encounter a bug, please raise an issue: https://github.com/bdalpe/phantom-cribl/issues

⚠️ Do not paste logs or configurations with sensitive data!

## Developing and Releasing

To compile the app, you will need to run the following commands from a Phantom server:

```shell
su phantom
git clone https://github.com/bdalpe/phantom-cribl
cd phantom-cribl
phenv python /opt/phantom/bin/compile_app.pyc -i
```

The compiled app will be placed in the parent directory and named `phantom-cribl.tgz`.