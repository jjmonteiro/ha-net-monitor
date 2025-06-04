---
name: Bug report
about: Report a problem with the net_monitor integration
title: "[Bug]: "
labels: bug
assignees: 
---

## Describe the issue
A clear and concise description of what the problem is.

## Version Info
- Home Assistant version:
- net_monitor version:

## Steps to Reproduce
1. 
2. 
3. 

## Expected Behavior
What did you expect to happen?

## Logs

To enable debug logs for `net_monitor`, add the following to your `configuration.yaml`:

```yaml
logger:
  logs:
    custom_components.net_monitor: debug
```

Then restart HA, wait 5 minutes and under Settings > System > Logs and select 'Download logs' from the upper right menu.

```
**Please paste debug logs below.**  
