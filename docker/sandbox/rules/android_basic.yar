// Regole YARA di base per APK/dex sospetti. Sono indicatori, non prove:
// un'app legittima può farne scattare qualcuna.

rule Android_DynamicCodeLoading
{
    meta:
        description = "Carica codice a runtime (tipico dei dropper)"
    strings:
        $a = "Ldalvik/system/DexClassLoader;"
        $b = "Ldalvik/system/InMemoryDexClassLoader;"
        $c = "Ldalvik/system/PathClassLoader;"
    condition:
        any of them
}

rule Android_RootCheck_Or_Su
{
    meta:
        description = "Cerca o invoca il binario su (root)"
    strings:
        $a = "/system/xbin/su"
        $b = "/system/bin/su"
        $c = "Superuser.apk"
    condition:
        2 of them
}

rule Android_SmsAbuse
{
    meta:
        description = "Invia SMS in modo programmatico e intercetta quelli in arrivo"
    strings:
        $send = "sendTextMessage"
        $recv = "android.provider.Telephony.SMS_RECEIVED"
        $abort = "abortBroadcast"
    condition:
        $send and ($recv or $abort)
}

rule Android_AccessibilityOverlay
{
    meta:
        description = "Accessibilità + overlay: schema dei banking trojan"
    strings:
        $acc = "android.accessibilityservice.AccessibilityService"
        $perform = "performGlobalAction"
        $overlay = "TYPE_APPLICATION_OVERLAY"
        $overlay2 = "android.permission.SYSTEM_ALERT_WINDOW"
    condition:
        $acc and $perform and any of ($overlay*)
}

rule Android_Telegram_C2
{
    meta:
        description = "Usa la Bot API di Telegram (spesso usata come C2 o per esfiltrare dati)"
    strings:
        $a = "api.telegram.org/bot"
    condition:
        $a
}
