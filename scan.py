import time

from main.Anywhere import (通达OA_v11_5_swfupload_sql, 通达OA_v11_5_任意用户登录, 通达OA_v11_6_insert_sql,
                           通达OA_v11_6_report_bi_sql, 通达OA_v11_6_任意文件删除_RCE, 通达OA_v11_7_后台sql注入,
                           通达OA_v11_7_在线用户登录, 通达OA_v11_8_api_任意文件上传, 通达OA_v11_8_getway_远程文件包含,
                           通达OA_v2014_get_contactlist, 通达OA_v2017_action_upload, 通达OA_v2017_任意用户登录,
                           通达OA_v11_8_logincheck, 通达OA_v11_8_后台包含xss, 通达OA_v11_9_getdata)

from main.ezoffice import (万户OA_download_ftp, 万户OA_download_http, 万户OA_download_old, 万户OA_fileupload_controller,
                           万户OA_office_任意文件上传, 万户OA_document_sql, 万户OA_smart_upload_文件上传,
                           万户OA_download_servelet)

from main.FineReport import (帆软_v8_get_json_任意文件读取, 帆软_v9_design_文件覆盖上传, 帆软_2012_信息泄露)

from main.HtianDL import (华天动力OA_8000版_sql)

from main.ioffice import (红帆OA_IOFILE_任意文件读取, 红帆OA_医疗云sql注入, 红帆OA_非医疗版_任意文件上传,
                          红帆OA_前台sql注入)

from main.kingdee import (金蝶OA_server_file_目录遍历, 金蝶OA_path_任意文件下载, 金蝶OA_Apusic应用服务器_目录遍历)

from main.Landray import (蓝凌OA_任意文件写入, 蓝凌OA_treeXml_远程命令执行, 蓝凌OA_datajson_命令执行,
                          蓝凌OA_custom_任意文件读取)
from main.Rev import (启莱OA_treelist_sql, 启莱OA_messageurl_sql, 启莱OA_treelist_sql)

from main.seefly import (致翔OA_msglog_sql)

from main.seeyou import 致远OA_A6_createMysql_数据库敏感信息泄露, 致远OA_A6_DownExcelBeanServlet_用户敏感信息下载, \
    致远OA_A6_initDataAssess_用户敏感信息泄露, \
    致远OA_A6_setextno_SQL注入Getshell, 致远OA_A6_test_SQL注入Getshell, 致远OA_A8_htmlofficeservlet_RCE, \
    致远OA_getSessionList_Session泄漏, 致远OA_ajax_登录绕过_任意文件上传, 致远OA_webmail_任意文件下载, \
    致远OA_Session泄露_任意文件上传, 致远OA_Fastjson_反序列化, 致远OA_A6_config_jsp敏感信息泄露, \
    致远OA_A8_status_jsp敏感信息泄露

from main.smart import (智明OA_EmailDownload_任意文件下载)

from main.weaver import 泛微_E_Cology9_browser_SQL注入漏洞,泛微OA_Bash远程代码执行漏洞, 泛微云桥任意文件读取漏洞, 泛微OA_E_Cology_数据库配置信息泄漏, 泛微OA_V8前台SQL注入, \
    泛微协同WorkflowServiceXml_RCE漏洞
from main.weaver import 泛微协同_weaver_common_Ctrl_任意文件上传漏洞, 泛微协同WorkflowCenterTreeData接口SQL注入漏洞, 泛微OA_V9_文件上传漏洞, \
    泛微OA_ln_FileDownload_接口任意文件读取漏洞
from main.weaver import 泛微_e_office_未授权访问漏洞, 泛微OA_文件上传漏洞_CNVD_2021_49104, 泛微_e_office_officeserver_php_任意文件读取漏洞, \
    泛微OA_V8_group_xml_sql注入漏洞, 泛微协同敏感信息泄漏, 泛微协同SQL注入漏洞_CNVD_2021_3320, 泛微云桥getdatasql注入漏洞, 泛微协同HrmCareerApplyPerView_SQL注入漏洞, \
    泛微协同jqueryFileTree_jsp_目录遍历漏洞, 泛微OA_Verify_QuickLogin, 泛微OA_mysql_config数据库信息泄漏, 泛微OA_signnature_任意文件访问, \
    泛微OA_uploaderOperate_jsp文件上传漏洞, 泛微OA_V10_前台sql, 泛微OA_ktreeuploadAction文件上传漏洞, 泛微OA_v10_upload, \
     泛微_e_office_文件上传漏洞

from main.XinDian import 新点OA_Excel_敏感信息泄露

from main.YMoa import 一米OA_beifenAction_任意文件读取

from main.yonyou import 用友BeanShell命令执行漏洞, 用友NC_OA任意文件上传, 用友NC_ERP注入漏洞, 用友NC_U8_test_sql注入漏洞, 用友NC目录遍历和任意文件读取漏洞
from main.yonyou import 用友畅捷通T_updata_任意文件上传, 用友U8OA_getSessionList敏感信息泄漏漏洞, 用友FE协作办公平台目录遍历漏洞, 用友NC_NCFindWeb_任意文件读取漏洞, \
    用友NC_XbrlPersistenceServlet反序列化漏洞, 用友_U8_f5_sql, 用友GRP_u8_upload_data,用友KSOA_imageUpload_RCE漏洞


def scan(oa_name, target, mode,scan_option):
    if target == "":
        print("Input Error")
        return 0
    if oa_name == "通达OA":
        # 调用处理"通达OA"的函数
        process_tongda_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "万户OA":
        # 调用处理"万户OA"的函数
        process_wanhu_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "帆软OA":
        # 调用处理"帆软OA"的函数
        process_fanruan_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "华天动力OA":
        # 调用处理"华天动力OA"的函数
        process_huatian_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "红帆OA":
        # 调用处理"红帆OA"的函数
        process_hongfan_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "金蝶OA":
        # 调用处理"金蝶OA"的函数
        process_jindie_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "蓝凌OA":
        # 调用处理"蓝凌OA"的函数
        process_lanling_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "启莱OA":
        # 调用处理"启莱OA"的函数
        process_qilai_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "致翔OA":
        # 调用处理"致翔OA"的函数
        process_zhixiang_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "致远OA":
        # 调用处理"致远OA"的函数
        process_zhiyuan_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "智明OA":
        # 调用处理"智明OA"的函数
        process_zhiming_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "泛微OA":
        # 调用处理"泛微OA"的函数
        process_fanwei_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "新点OA":
        # 调用处理"新点OA"的函数
        process_xindian_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "一米OA":
        # 调用处理"一米OA"的函数
        process_yimi_oa(target, mode,scan_option)
        print("扫描结束")
    elif oa_name == "用友OA":
        # 调用处理"用友OA"的函数
        process_yongyou_oa(target, mode,scan_option)
        print("扫描结束")
    else:
        print("Invalid OA name.")


def fileRead(filename):
    try:
        f = open(filename, 'r')
        url = f.readlines()
        f.close()
        return url
    except Exception as e:
        print(e)
        return


def process_tongda_oa(target, mode,scan_option):
    oa_list = ['通达OA_v11_5_swfupload_sql', '通达OA_v11_5_任意用户登录', '通达OA_v11_6_insert_sql',
               '通达OA_v11_6_report_bi_sql', '通达OA_v11_6_任意文件删除_RCE', '通达OA_v11_7_后台sql注入',
               '通达OA_v11_7_在线用户登录', '通达OA_v11_8_api_任意文件上传', '通达OA_v11_8_getway_远程文件包含',
               '通达OA_v2014_get_contactlist', '通达OA_v2017_action_upload', '通达OA_v2017_任意用户登录',
               '通达OA_v11_8_logincheck', '通达OA_v11_8_后台包含xss', '通达OA_v11_9_getdata']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]


    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_wanhu_oa(target, mode,scan_option):
    oa_list = ['万户OA_download_ftp', '万户OA_download_http', '万户OA_download_old',
               '万户OA_fileupload_controller', '万户OA_office_任意文件上传', '万户OA_document_sql',
               '万户OA_smart_upload_文件上传', '万户OA_download_servelet']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_fanruan_oa(target, mode,scan_option):
    oa_list = ['帆软_v8_get_json_任意文件读取', '帆软_v9_design_文件覆盖上传', '帆软_2012_信息泄露']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_huatian_oa(target, mode,scan_option):
    oa_list = ['华天动力OA_8000版_sql']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_hongfan_oa(target, mode, scan_option):
    oa_list = ['红帆OA_IOFILE_任意文件读取', '红帆OA_医疗云sql注入', '红帆OA_非医疗版_任意文件上传',
               '红帆OA_前台sql注入']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_jindie_oa(target, mode,scan_option):
    oa_list = ['金蝶OA_server_file_目录遍历', '金蝶OA_path_任意文件下载', '金蝶OA_Apusic应用服务器_目录遍历']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_lanling_oa(target, mode,scan_option):
    oa_list = ['蓝凌OA_任意文件写入', '蓝凌OA_treeXml_远程命令执行', '蓝凌OA_datajson_命令执行',
               '蓝凌OA_custom_任意文件读取']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_qilai_oa(target, mode,scan_option):
    oa_list = ['启莱OA_treelist_sql', '启莱OA_messageurl_sql', '启莱OA_treelist_sql']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_zhixiang_oa(target, mode,scan_option):
    oa_list = ['致翔OA_msglog_sql']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_zhiyuan_oa(target, mode,scan_option):
    oa_list = ['致远OA_A6_createMysql_数据库敏感信息泄露', '致远OA_A6_DownExcelBeanServlet_用户敏感信息下载',
               '致远OA_A6_initDataAssess_用户敏感信息泄露',
               '致远OA_A6_setextno_SQL注入Getshell', '致远OA_A6_test_SQL注入Getshell',
               '致远OA_A8_htmlofficeservlet_RCE',
               '致远OA_getSessionList_Session泄漏', '致远OA_ajax_登录绕过_任意文件上传', '致远OA_webmail_任意文件下载',
               '致远OA_Session泄露_任意文件上传', '致远OA_A6_config_jsp敏感信息泄露',
               '致远OA_A8_status_jsp敏感信息泄露',
               '致远OA_Fastjson_反序列化']

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_zhiming_oa(target, mode,scan_option):
    oa_list = ['智明OA_EmailDownload_任意文件下载']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_fanwei_oa(target, mode,scan_option):
    oa_list = ['泛微OA_E_Cology_数据库配置信息泄漏', '泛微OA_V8前台SQL注入', '泛微协同WorkflowServiceXml_RCE漏洞',
                '泛微OA_Bash远程代码执行漏洞', '泛微云桥任意文件读取漏洞',
                '泛微协同_weaver_common_Ctrl_任意文件上传漏洞', '泛微协同WorkflowCenterTreeData接口SQL注入漏洞', '泛微OA_V9_文件上传漏洞',
                '泛微OA_ln_FileDownload_接口任意文件读取漏洞', '泛微_e_office_未授权访问漏洞', '泛微OA_文件上传漏洞_CNVD_2021_49104',
                '泛微_e_office_officeserver_php_任意文件读取漏洞', '泛微OA_V8_group_xml_sql注入漏洞', '泛微协同敏感信息泄漏漏',
                '泛微协同SQL注入漏洞(泛微协同SQL注入漏洞_CNVD_2021_3320-2021-3320)', '泛微云桥getdatasql注入漏洞', '泛微协同HrmCareerApplyPerView_SQL注入漏洞', '泛微协同jqueryFileTree_jsp_目录遍历漏洞',
                '泛微OA_Verify_QuickLogin', '泛微OA_mysql_config数据库信息泄漏', '泛微OA_signnature_任意文件访问',
                '泛微OA_uploaderOperate_jsp文件上传漏洞', '泛微OA_V10_前台sql', ' ', '泛微OA_ktreeuploadAction文件上传漏洞',
                '泛微OA_v10_upload', ' 泛微_e_office_文件上传漏洞', '泛微_E_Cology9_browser_SQL注入漏洞']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.01)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.01)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_xindian_oa(target, mode,scan_option):
    oa_list = ['新点OA_Excel_敏感信息泄露']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_yimi_oa(target, mode,scan_option):
    oa_list = ['一米OA_beifenAction_任意文件读取']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass


def process_yongyou_oa(target, mode,scan_option):
    global stop_scan
    oa_list = ['用友BeanShell命令执行漏洞', '用友NC_OA任意文件上传', '用友NC_U8_test_sql注入漏洞', '用友FE协作办公平台目录遍历漏洞',
               '用友畅捷通T_updata_任意文件上传', '用友U8OA_getSessionList敏感信息泄漏漏洞', '用友FE协作办公平台目录遍历漏洞', '用友NC_NCFindWeb_任意文件读取漏洞',
               '用友NC_XbrlPersistenceServlet反序列化漏洞', '用友_U8_f5_sql', '用友GRP_u8_upload_data', '用友KSOA_imageUpload_RCE漏洞']

    if scan_option == "ALL":
        scan_scripts = oa_list
    else:
        scan_scripts = [scan_option]

    if mode == 'single':
        for i in scan_scripts:
            eval(i + ".main(target)")
            time.sleep(0.2)
    elif mode == 'list':
        if isinstance(target, list):
            for url in target:
                for i in scan_scripts:
                    eval(i + ".main(url)")
                    time.sleep(0.2)
        else:
            print("Invalid target for list mode. Please provide a list of URLs.")
    else:
        print("Invalid scan mode. Please provide either 'single' or 'list'.")
    pass
