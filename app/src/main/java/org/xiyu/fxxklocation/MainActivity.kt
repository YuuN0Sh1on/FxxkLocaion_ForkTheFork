package org.xiyu.fxxklocation

import android.app.Activity
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.widget.ScrollView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#F5F5F5"))
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 80, 64, 80)
        }

        // Title: Name + Version
        layout.addView(TextView(this).apply {
            text = "FxxkLocation v1.0.0"
            textSize = 26f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#1B5E20"))
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 48)
        })

        // Readme & Disclaimer Content
        val readmeSections = listOf(
            "⚠️ 核心声明" to "本项目及所有相关模块仅供个人学习、Android 逆向工程研究以及安全防御机制分析使用。\n\n本项目旨在探讨“本地权限与布尔值校验”的脆弱性，通过 Hook 技术演示本地鉴权的绕过方式，以此提醒开发者采用更安全的鉴权方案。\n\n请于下载测试后 24 小时内自觉删除。不可倒卖该资源，不可用于盈利，不可在中国大陆区域传播。",
            "⚖️ 权利与下架通知" to "本项目纯属个人对逆向技术的兴趣探索。若本模块对您的知识产权或商业权益造成了实质性侵害，请随时通过以下邮箱联系我：\n\nmaixiyumc@gmail.com\n\n我将在收到权利人的有效通知后，第一时间核实并下架/删除本项目的所有相关代码与模块产物。",
            "🚫 严禁违规用途" to "请勿将本模块用于校园跑软件、企业签到打卡、网约车抢单、LBS 游戏作弊等任何违规、违法或损害他人利益的场景。\n\n责任归属：由于滥用本模块所引发的目标应用账号封禁、法律纠纷或任何形式的经济/权益损失，概由使用者自行承担。Fakelocation 原作者及受损方有权向您追究责任。本模块作者概不负责。",
            "🛠️ 设备风险提示" to "Xposed/LSPosed 模块对系统底层的修改具有一定风险，可能会引起应用闪退（Crash）、系统软重启（Soft Reboot）或卡开机动画（Bootloop）。请确保您具备基本的“救砖”能力（如通过 ADB 或 Recovery 终端禁用模块）。"
        )

        for ((title, content) in readmeSections) {
            // Section Title
            layout.addView(TextView(this).apply {
                text = title
                textSize = 18f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor("#D32F2F")) // 红色警告色
                setPadding(0, 32, 0, 12)
            })
            // Section Body
            layout.addView(TextView(this).apply {
                text = content
                textSize = 15f
                setTextColor(Color.parseColor("#424242"))
                setLineSpacing(8f, 1.2f)
            })
        }

        root.addView(layout)
        setContentView(root)
    }
}