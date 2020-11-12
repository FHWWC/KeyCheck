 protected void Page_Load(object sender, EventArgs e)
        {
            wbfm = this;
            if (!IsPostBack)
            {
                ViewState["keys"] = keys;
                ViewState["state"] = BtnState;
                ViewState["canuse"] = canUse;
                ViewState["ProductN"] = productN;
                ViewState["KeyCheckR"] = "";

                if(Session["checkOption1"]==null)
                {
                    Session["checkOption1"] = CKBX.Items[0].Selected;
                }
                else
                {
                    CKBX.Items[0].Selected = (bool)Session["checkOption1"];
                }
                if(Session["checkOption4"]==null)
                {
                    Session["checkOption4"] = CKBX.Items[3].Selected;
                }
                else
                {
                    CKBX.Items[3].Selected = (bool)Session["checkOption4"];
                }


                ConfigList.Items.Add("遍历所有证书");
                ConfigList.SelectedIndex = 0;
                LoadConfig.Load(configFile + "PkeyData.xml");
                for (int i = 0; i < LoadConfig.FirstChild.ChildNodes.Count; i++)
                {
                    ConfigList.Items.Add(LoadConfig.FirstChild.ChildNodes[i].Attributes[1].InnerText);
                }
            }
        }
        public const string KeyFormat = @"(?!^.*N.*N.*$)([BCDFGHJKMPQRTVWXY2-9N]{5}\-){4}[BCDFGHJKMPQRTVWXY2-9N]{4}[BCDFGHJKMPQRTVWXY2-9]";
        XmlDocument LoadConfig = new XmlDocument();
        public static string configFile = "\\PKeyConfig\\";
        bool isMul;
        
        public async void CheckKeys(object sender, EventArgs e)
        {
            //submit.Visible = false;
            //int keyLength = Request.Form["keybox"].Length;
            //int keyLength = keybox.Value.Length;

            keybox.Value = keybox.Value.ToUpper();
            string[] group = null;
            MatchCollection abc = Regex.Matches(keybox.Value.ToString(), KeyFormat);
            if (abc.Count > 0)
            {
                int i = 0;
                group = new string[abc.Count];
                foreach (var keys in abc)
                {
                    group[i] = keys.ToString();
                    i++;
                }

                if (abc.Count == 1)
                {
                    CKResult.Visible = false;
                    ResultTable.Visible = true;

                    keybox.Value = group[0];
                    isMul = false;
                    
                    //开始检测密钥，此方法请你自行编写
                    Checking(group[0]);
                }
                else if (abc.Count > 10)
                {
                //请自定义你的弹出窗口
                    OpenPOOP("一次不能检测超过10个Key");
                }
                else
                {
                    CKResult.Value = "";
                    CKResult.Visible = true;
                    ResultTable.Visible = false;

                    if (ConfigList.SelectedIndex != 0)
                    {
                        OpenPOOP("如果您要跑多个码，则不能指定一个证书进行检测，请选择“遍历所有证书选项”继续检测.");
                        CKResult.Value += "已经从您粘贴的文本上获得了" + abc.Count + "个密钥，如果您要跑多个码，则不能指定一个证书进行检测，请选择“遍历所有证书选项”继续检测.\n";
                        return;
                    }

                    CKResult.Value += "已经从您粘贴的文本上获得了" + abc.Count + "个密钥，现在开始检测...\n";
                    for (int aa = 0; aa < group.Length; aa++)
                    {
                        CKResult.Value += "\n\n 正在检测 " + group[aa];
                        isMul = true;
                        
                    //开始检测密钥，此方法请你自行编写
                        Checking(group[aa]);

                        while (!isFinished)
                        {
                            await Task.Delay(1000);
                        }
                        await Task.Delay(500);
                    }
                    CKResult.Value += "\n\n\n All done. 全部检测完成！";
                }
            }
            else
            {
                OpenPOOP("密钥长度不正确或输入的内容里不包含密钥！！");
                return;
            }
        }
        
        
        
        //开始检测密钥，此方法请你自行编写
        //检测密钥请参考 https://github.com/FHWWC/KeyCheck/blob/master/KeyCheck.cs
        
        
        
        
        [DllImport(@"pidgenx.dll", EntryPoint = "PidGenX", CharSet = CharSet.Auto)]
        public static extern int PidGenX(string ProductKey, string PkeyPath, string MSPID, string oemId, IntPtr ProductID, IntPtr DigitalProductID, IntPtr DigitalProductID4);
        
                public static string GetString(byte[] bytes, int index)
        {
            int n = index;
            while (!(bytes[n] == 0 && bytes[n + 1] == 0)) n++;
            return Encoding.ASCII.GetString(bytes, index, n - index).Replace("\0", "");
        }
        public static string GetEPIDStart()
        {
            var osBuild = Environment.OSVersion.Version.Build;
            string ePidStart;

            if (osBuild >= 10000)
            {
                ePidStart = "03612";
            }
            else if (osBuild >= 9600)
            {
                ePidStart = "06401";
            }
            else if (osBuild >= 9200)
            {
                ePidStart = "05426";
            }
            else
            {
                ePidStart = "55041";
            }
            return ePidStart;
        }
        
                public static readonly byte[] MSActivationServerHmacKey =
        {
                    0xfe, 0x31, 0x98, 0x75, 0xfb, 0x48, 0x84, 0x86, 0x9c, 0xf3, 0xf1, 0xce, 0x99, 0xa8, 0x90, 0x64,
                    0xab, 0x57, 0x1f, 0xca, 0x47, 0x04, 0x50, 0x58, 0x30, 0x24, 0xe2, 0x14, 0x62, 0x87, 0x79, 0xa0,
        };
        
        
        
        
        //远程连接到主机检测略过
