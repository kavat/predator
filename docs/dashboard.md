# Predator dashboard (under construction)
Dashboard can manage three sources:

- **Elasticsearch**
   ```python
   READ_THREATS_FROM_ES = True
   READ_THREATS_FROM_LOCAL_DB = False
   READ_THREATS_FROM_SQLITE = False
    ```
- **SQLite**
   ```python
   READ_THREATS_FROM_ES = False
   READ_THREATS_FROM_LOCAL_DB = False
   READ_THREATS_FROM_SQLITE = True
   ```
- **Local json**
   ```python
   READ_THREATS_FROM_ES = False
   READ_THREATS_FROM_LOCAL_DB = True
   READ_THREATS_FROM_SQLITE = False
   ```

**Note**: One of sources above has to be set in dashboard/config.py configuration file and shall be the same configured in main config.py.

After set Predator as proxy in browser (refer to [config.py](./config.md) for feature enabling, generate CA through API and import in browser in order to complete SSL interception), visit [http://predator.dashboard](http://predator.dashboard).
**Note**: as default Dashboard is only reachable through Proxy at LINK_DASHBOARD URL because bind over 127.0.0.1, changing dasboard/config.py configuration Dasboard can be reached directly.
