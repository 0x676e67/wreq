pub(super) fn with_system(builder: &mut super::matcher::Builder) {
    let Ok(settings) = windows_registry::CURRENT_USER
        .open("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
    else {
        return;
    };

    if settings.get_u32("ProxyEnable").unwrap_or(0) == 0 {
        return;
    }

    if let Ok(val) = settings.get_string("ProxyServer") {
        if builder.http.is_empty() {
            builder.http = val.clone();
        }
        if builder.https.is_empty() {
            builder.https = val;
        }
    }

    if builder.no.is_empty() {
        if let Ok(val) = settings.get_string("ProxyOverride") {
            builder.no = val
                .split(';')
                .map(|s| s.trim())
                .collect::<Vec<&str>>()
                .join(",")
                .replace("*.", "");
        }
    }
}
