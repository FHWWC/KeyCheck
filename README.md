# 密钥检测/密钥分享/密钥查询 等微软产品激活相关

密钥检测工具网页版：http://pkeytools.azurewebsites.net （永久域名）


密钥检测API，方式GET，返回XML文档：https://pkeytools.azurewebsites.net/CK/?K= 密钥 &nodb= 0或1 &coem= 0或1   （去掉空格）
Example 1 https://pkeytools.azurewebsites.net/CK/?K=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
Example 2 https://pkeytools.azurewebsites.net/CK/?K=XXXXX-XXXXX-XXXXX-XXXXX-XXXXX&nodb=1&coem=1

K参数：你要检测的密钥。仅支持单个密钥；
nodb参数（可选参数）：是否连接已封密钥数据库。有效值 0或1；值为1则检测前不先连接已封密钥数据库查询是否被封，值为0则连接。
coem参数（可选参数）：检测OEM密钥的可用次数（如果支持）。有效值 0或1；值为1则检测可用次数，值为0则不检测。


【暂时关闭】备用域名：https://pkeytool.tk （时间缘故，此网站可能不会保持最新）

# 说明：
检测错误代码请使用客户端，主机暂未配置好（学生党表示正在吃土），敬请谅解。
# 本站当前无广告，无推广，无付费
