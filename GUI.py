import sys
import threading
import wx
from scan import scan, fileRead
from PIL import Image, ImageFilter


class TextRedirector:
    def __init__(self, widget):
        self.widget = widget

    def write(self, text):
        self.widget.AppendText(text)

    def flush(self):
        pass
#若取消背景，删除掉这个类，并将OAScanner的panel注释生效即可
# class BackgroundPanel(wx.Panel):
#     def __init__(self, parent, imagePath):
#         super().__init__(parent)
#         self.image = wx.Bitmap("./background.jpg")
#         self.Bind(wx.EVT_PAINT, self.OnPaint)
#
#     def OnPaint(self, event):
#         dc = wx.BufferedPaintDC(self)
#         dc.DrawBitmap(self.image, 0, 0)

class OAScanner(wx.Frame):
    def __init__(self, parent, title):
        wx.Frame.__init__(self, parent, title=title, size=(800, 600))

        panel = wx.Panel(self)  #没有背景的输出代码
        #panel = BackgroundPanel(self, "background.jpg")  #与上方类配合增加背景

        self.scan_mode_var = wx.RadioButton(panel, label="单个URL扫描", pos=(20, 20))
        self.scan_mode_var.Bind(wx.EVT_RADIOBUTTON, self.on_single_url_scan_selected)
        self.single_url_input = wx.TextCtrl(panel, pos=(150, 20), size=(600, -1))

        self.list_file_button = wx.RadioButton(panel, label="文件批量扫描", pos=(20, 60))
        self.list_file_button.Bind(wx.EVT_RADIOBUTTON, self.on_list_file_scan_selected)
        self.file_input = wx.TextCtrl(panel, pos=(150, 60), size=(520, -1), style=wx.TE_READONLY)
        self.file_button = wx.Button(panel, label="选择文件", pos=(680, 60))
        self.file_button.Bind(wx.EVT_BUTTON, self.select_file)

        self.oa_option_text = wx.StaticText(panel, label="选择OA系统", pos=(20, 105))
        self.oa_option_var = wx.ComboBox(panel, choices=["通达OA", "万户OA", "帆软OA", "华天动力OA", "红帆OA", "金蝶OA",
                                                         "蓝凌OA", "启莱OA", "致翔OA", "致远OA", "智明OA", "泛微OA",
                                                         "新点OA", "一米OA", "用友OA"],
                                         value="选择OA系统", pos=(120, 100), size=(150, -1),
                                         style=wx.CB_READONLY)
        self.scan_option_text = wx.StaticText(panel, label="选择扫描脚本", pos=(300, 105))
        self.scan_option_var = wx.ComboBox(panel, choices=[], value="", pos=(420, 100), size=(200, -1),
                                           style=wx.CB_READONLY)
        self.scan_button = wx.Button(panel, label="开始扫描", pos=(680, 100))
        self.scan_button.Bind(wx.EVT_BUTTON, self.start_scan)
        self.oa_option_var.Bind(wx.EVT_COMBOBOX, self.on_oa_selected)

        self.output = wx.TextCtrl(panel, pos=(20, 150), size=(750, 350),
                                  style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)


        self.export_button = wx.Button(panel, label="导出日志", pos=(580, 520))
        self.export_button.Bind(wx.EVT_BUTTON, self.save_log)

        self.clear_button = wx.Button(panel, label="清屏", pos=(680, 520))
        self.clear_button.Bind(wx.EVT_BUTTON, self.clear_output)

        sys.stdout = TextRedirector(self.output)
        sys.stderr = TextRedirector(self.output)

        self.Show()

    def on_single_url_scan_selected(self, event):
        self.single_url_input.SetEditable(True)
        self.file_input.SetEditable(False)

    def on_list_file_scan_selected(self, event):
        self.single_url_input.SetEditable(False)
        self.file_input.SetEditable(True)

    def select_file(self, event):
        file_dialog = wx.FileDialog(self, "选择文件", "", "", "所有文件 (*.*)|*.*", wx.FD_OPEN | wx.FD_FILE_MUST_EXIST)
        if file_dialog.ShowModal() == wx.ID_CANCEL:
            return
        self.file_input.SetValue(file_dialog.GetPath())

    def on_oa_selected(self, event):
        oa_name = event.GetString()
        if oa_name == "红帆OA":
            self.scan_option_var.SetItems(
                ["ALL", "红帆OA_IOFILE_任意文件读取", "红帆OA_非医疗版_任意文件上传", "红帆OA_前台sql注入",
                 "红帆OA_医疗云sql注入"])
        elif oa_name == '万户OA':
            self.scan_option_var.SetItems(
                ["ALL","万户OA_document_sql","万户OA_download_ftp","万户OA_download_http","万户OA_download_old",
                 "万户OA_download_servelet","万户OA_fileupload_controller","万户OA_office_任意文件上传","万户OA_smart_upload_文件上传"
                 ])
        elif oa_name == '帆软OA':
            self.scan_option_var.SetItems(
                ["ALL", "帆软_2012_信息泄露", "帆软_v8_get_json_任意文件读取", "帆软_v9_design_文件覆盖上传"])
        elif oa_name == '通达OA':
            self.scan_option_var.SetItems(
                ["ALL", "通达OA_v11_5_swfupload_sql", "通达OA_v11_5_任意用户登录", "通达OA_v11_6_insert_sql","通达OA_v11_6_report_bi_sql",
                 "通达OA_v11_6_任意文件删除_RCE","通达OA_v11_7_后台sql注入","通达OA_v11_7_在线用户登录","通达OA_v11_8_api_任意文件上传",
                 "通达OA_v11_8_getway_远程文件包含","通达OA_v11_8_logincheck","通达OA_v11_8_后台包含xss","通达OA_v11_9_getdata"
                 "通达OA_v2014_get_contactlist","通达OA_v2017_action_upload","通达OA_v2017_任意用户登录"])
        elif oa_name == '华天动力OA':
            self.scan_option_var.SetItems(
                ["ALL", "华天动力OA_8000版_sql"])
        elif oa_name == '金蝶OA':
            self.scan_option_var.SetItems(
                ["ALL", "金蝶OA_Apusic应用服务器_目录遍历", "金蝶OA_path_任意文件下载", "金蝶OA_server_file_目录遍历"])
        elif oa_name == '蓝凌OA':
            self.scan_option_var.SetItems(
                ["ALL", "蓝凌OA_custom_任意文件读取", "蓝凌OA_datajson_命令执行", "蓝凌OA_treeXml_远程命令执行",
                 "蓝凌OA_任意文件写入"])
        elif oa_name == '启莱OA':
            self.scan_option_var.SetItems(
                ["ALL", "启莱OA_closeMsg_sql", "启莱OA_messageurl_sql", "启莱OA_treelist_sql"])
        elif oa_name == '致翔OA':
            self.scan_option_var.SetItems(
                ["ALL", "致翔OA_msglog_sql"])
        elif oa_name == '致远OA':
            self.scan_option_var.SetItems(
                ["ALL", "致远OA_A6_config_jsp敏感信息泄露", "致远OA_A6_createMysql_数据库敏感信息泄露", "致远OA_A6_DownExcelBeanServlet_用户敏感信息下载",
                 "致远OA_A6_initDataAssess_用户敏感信息泄露","致远OA_A6_setextno_SQL注入Getshell","致远OA_A6_test_SQL注入Getshell",
                 "致远OA_A8_htmlofficeservlet_RCE","致远OA_A8_status_jsp敏感信息泄露","致远OA_ajax_登录绕过_任意文件上传","致远OA_Fastjson_反序列化",
                 "致远OA_getSessionList_Session泄漏","致远OA_Session泄露_任意文件上传","致远OA_webmail_任意文件下载"])
        elif oa_name == '用友OA':
            self.scan_option_var.SetItems(
                ["ALL", "用友FE协作办公平台目录遍历漏洞", "用友BeanShell命令执行漏洞", "用友NC目录遍历和任意文件读取漏洞","用友NC_ERP注入漏洞","用友NC_NCFindWeb_任意文件读取漏洞","用友U8OA_getSessionList敏感信息泄漏漏洞","用友NC_U8_test_sql注入漏洞","用友NC_OA任意文件上传","用友NC_XbrlPersistenceServlet反序列化漏洞","用友KSOA_imageUpload_RCE漏洞"
                 "用友_U8_f5_sql","用友GRP_u8_upload_data","用友畅捷通T_updata_任意文件上传"])
        elif oa_name == '智明OA':
            self.scan_option_var.SetItems(
                ["ALL", "智明OA_EmailDownload_任意文件下载"])
        elif oa_name == '泛微OA':
            self.scan_option_var.SetItems(
                ["ALL", "泛微_E_Cology9_browser_SQL注入漏洞",
                 "泛微_e_office_officeserver_php_任意文件读取漏洞","泛微_e_office_未授权访问漏洞",
                 "泛微_e_office_文件上传漏洞","泛微OA_Bash远程代码执行漏洞","泛微OA_E_Cology_数据库配置信息泄漏","泛微OA_ktreeuploadAction文件上传漏洞",
                 "泛微OA_ln_FileDownload_接口任意文件读取漏洞","泛微OA_mysql_config数据库信息泄漏",
                 "泛微OA_signnature_任意文件访问","泛微OA_uploaderOperate_jsp文件上传漏洞",
                 "泛微OA_V8_group_xml_sql注入漏洞","泛微OA_V8前台SQL注入","泛微OA_V9_文件上传漏洞",
                 "泛微OA_v10_upload","泛微OA_V10_前台sql","泛微OA_Verify_QuickLogin",
                 "泛微OA_文件上传漏洞_CNVD_2021_49104","泛微协同_weaver_common_Ctrl_任意文件上传漏洞"
                 "泛微协同HrmCareerApplyPerView_SQL注入漏洞","泛微协同jqueryFileTree_jsp_目录遍历漏洞",
                 "泛微协同SQL注入漏洞_CNVD_2021_3320","泛微协同WorkflowCenterTreeData接口SQL注入漏洞",
                 "泛微协同WorkflowServiceXml_RCE漏洞","泛微协同敏感信息泄漏","泛微云桥getdatasql注入漏洞",
                 "泛微云桥任意文件读取漏洞"
                 ""])
        elif oa_name == '新点OA':
            self.scan_option_var.SetItems(
                ["ALL", "新点OA_Excel_敏感信息泄露"])
        elif oa_name == '一米OA':
            self.scan_option_var.SetItems(
                ["ALL", "一米OA_beifenAction_任意文件读取"])
        else:
            self.scan_option_var.SetItems([])

    def start_scan(self, event):
        scan_thread = threading.Thread(target=self.run_scan)
        scan_thread.start()

    def run_scan(self):
        if self.scan_mode_var.GetValue():
            mode = 'single'
            target = self.single_url_input.GetValue()
        elif self.list_file_button.GetValue():
            mode = 'list'
            target = fileRead(self.file_input.GetValue())
        else:
            self.output.AppendText("请选择扫描模式：单个URL扫描或文件批量扫描。\n")
            return
        oa_name = self.oa_option_var.GetValue()
        if oa_name == "选择OA系统":
            self.output.AppendText("请选择OA系统。\n")
            return
        scan_option = self.scan_option_var.GetValue()
        if scan_option == "":
            self.output.AppendText("请选择扫描脚本。\n")
            return
        scan(oa_name, target, mode, scan_option)



    def save_log(self, event):
        file_dialog = wx.FileDialog(self, "保存日志", "", "", "文本文件 (*.txt)|*.txt",
                                    wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        if file_dialog.ShowModal() == wx.ID_CANCEL:
            return
        with open(file_dialog.GetPath(), "w") as file:
            file.write(self.output.GetValue())

    def clear_output(self, event):
        self.output.Clear()

if __name__ == "__main__":
    app = wx.App(False)
    frame = OAScanner(None, "OA 扫描器")
    app.MainLoop()
