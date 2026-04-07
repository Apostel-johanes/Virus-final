#define _CRT_SECURE_NO_WARNINGS
#include <gtk/gtk.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <setupapi.h>
#include <devguid.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "User32.lib")

#define PASSWORD "2002"
#define USB_NEEDED 3

/* =====================================================
   STRUCT & GLOBALS
===================================================== */
typedef struct {
    int hide;
    int crypt;
} ActionParams;

typedef struct {
    HWND hwnd;
    int usb_count;
    gboolean auto_mode;
    char target_folder[MAX_PATH];
    GtkApplication *app;
} AppData;

GtkWindow *main_window;
GtkWidget *password_entry;
AppData app_data = {0};

/* =====================================================
   SIMPLE USB DETECTION (Compatibilité améliorée)
===================================================== */
int get_usb_count() {
    int count = 0;

    // Méthode 1: Utiliser GetLogicalDrives et GetDriveType
    DWORD drives = GetLogicalDrives();

    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char drive[4];
            sprintf(drive, "%c:\\", 'A' + i);

            UINT type = GetDriveTypeA(drive);
            if (type == DRIVE_REMOVABLE) {
                count++;
            }
        }
    }

    return count;
}

/* =====================================================
   MESSAGE DIALOGS - GTK4 VERSION
===================================================== */
void on_message_dialog_response(GtkDialog *dialog, int response, gpointer user_data) {
    gtk_window_destroy(GTK_WINDOW(dialog));
}

void show_message_dialog(const char *title, const char *message) {
    GtkWidget *dialog = gtk_message_dialog_new_with_markup(main_window,
                                                          GTK_DIALOG_MODAL,
                                                          GTK_MESSAGE_INFO,
                                                          GTK_BUTTONS_OK,
                                                          "<span foreground='#b8860b'><b>%s</b></span>\n\n%s",
                                                          title, message);
    gtk_window_set_title(GTK_WINDOW(dialog), title);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_widget_set_margin_start(content, 20);
    gtk_widget_set_margin_end(content, 20);
    gtk_widget_set_margin_top(content, 20);
    gtk_widget_set_margin_bottom(content, 20);

    g_signal_connect(dialog, "response", G_CALLBACK(on_message_dialog_response), NULL);
    gtk_widget_show(dialog);
}

/* =====================================================
   CRYPTO
===================================================== */
void crypt_file(const char *path, int do_encrypt) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD size = GetFileSize(hFile, NULL);
    if (!size || size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return;
    }

    BYTE *data = (BYTE*)malloc(size);
    if (!data) {
        CloseHandle(hFile);
        return;
    }

    DWORD read;
    if (!ReadFile(hFile, data, size, &read, NULL)) {
        free(data);
        CloseHandle(hFile);
        return;
    }

    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(data);
        CloseHandle(hFile);
        return;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        free(data);
        CloseHandle(hFile);
        return;
    }

    if (!CryptHashData(hHash, (BYTE*)PASSWORD, strlen(PASSWORD), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(data);
        CloseHandle(hFile);
        return;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        free(data);
        CloseHandle(hFile);
        return;
    }

    DWORD len = size;
    if (do_encrypt) {
        if (!CryptEncrypt(hKey, 0, TRUE, 0, data, &len, size)) {
            // En cas d'erreur, on nettoie
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            free(data);
            CloseHandle(hFile);
            return;
        }
    } else {
        if (!CryptDecrypt(hKey, 0, TRUE, 0, data, &len)) {
            CryptDestroyKey(hKey);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            free(data);
            CloseHandle(hFile);
            return;
        }
    }

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, data, len, &read, NULL);
    SetEndOfFile(hFile);

    free(data);
    CloseHandle(hFile);
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}

/* =====================================================
   DIRECTORY WALK
===================================================== */
void process_dir(const char *dir, int hide, int crypt, gboolean show_message) {
    WIN32_FIND_DATAA fd;
    char search[MAX_PATH];
    sprintf(search, "%s\\*", dir);

    HANDLE h = FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    int file_count = 0;
    int dir_count = 0;

    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, ".."))
            continue;

        char full[MAX_PATH];
        sprintf(full, "%s\\%s", dir, fd.cFileName);

        if (hide != -1) {
            SetFileAttributesA(full,
                hide ? FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                     : FILE_ATTRIBUTE_NORMAL);
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            process_dir(full, hide, crypt, FALSE);
            dir_count++;
        } else if (crypt != -1) {
            crypt_file(full, crypt);
            file_count++;
        }

    } while (FindNextFileA(h, &fd));

    FindClose(h);

    if (show_message) {
        char message[256];
        if (crypt != -1) {
            sprintf(message, "%d fichiers %s avec succès",
                   file_count, crypt ? "cryptés" : "décryptés");
            show_message_dialog(crypt ? "Cryptage" : "Décryptage", message);
        }
        if (hide != -1) {
            sprintf(message, "%d dossiers %s avec succès",
                   dir_count, hide ? "masqués" : "démasqués");
            show_message_dialog(hide ? "Masquage" : "Démasquage", message);
        }
    }
}

/* =====================================================
   AUTO MODE - USB INSERTION
===================================================== */
void check_auto_mode() {
    if (!app_data.auto_mode || app_data.target_folder[0] == '\0')
        return;

    int current_usb = get_usb_count();

    if (current_usb > 0 && app_data.usb_count == 0) {
        // USB branché - masquer et crypter
        process_dir(app_data.target_folder, 1, 1, TRUE);
        show_message_dialog("Auto-mode",
            "Fichiers/dossiers masqués et cryptés avec succès au branchement USB");
        app_data.usb_count = current_usb;
    }

    if (current_usb >= USB_NEEDED && app_data.usb_count < USB_NEEDED) {
        // 3 USB branchés - décrypter
        process_dir(app_data.target_folder, 0, 0, TRUE);
        show_message_dialog("Auto-mode",
            "Fichiers/dossiers démasqués et décryptés avec succès (3 USB détectés)");
        app_data.usb_count = current_usb;
    }

    app_data.usb_count = current_usb;
}

/* =====================================================
   FILE CHOOSER RESPONSE (GTK4)
===================================================== */
void on_folder_response(GtkDialog *dialog, int response, gpointer user_data) {
    ActionParams *p = (ActionParams*)user_data;

    if (response == GTK_RESPONSE_ACCEPT) {
        GFile *file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        char *folder = g_file_get_path(file);

        strcpy(app_data.target_folder, folder);

        if (p->hide == 1 && p->crypt == 1) {
            show_message_dialog("Opération",
                "Fichiers/dossiers masqués et cryptés avec succès");
        } else if (p->hide == 0 && p->crypt == 0) {
            show_message_dialog("Opération",
                "Fichiers/dossiers démasqués et décryptés avec succès");
        } else if (p->hide == 1 && p->crypt == -1) {
            show_message_dialog("Opération",
                "Fichiers/dossiers masqués avec succès");
        } else if (p->hide == 0 && p->crypt == -1) {
            show_message_dialog("Opération",
                "Fichiers/dossiers démasqués avec succès");
        }

        process_dir(folder, p->hide, p->crypt, FALSE);

        g_free(folder);
        g_object_unref(file);
    }

    gtk_window_destroy(GTK_WINDOW(dialog));
    free(p);
}

void choose_folder(int hide, int crypt) {
    GtkWidget *dialog = gtk_file_chooser_dialog_new(
        "Choisir un dossier",
        main_window,
        GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "Annuler", GTK_RESPONSE_CANCEL,
        "OK", GTK_RESPONSE_ACCEPT,
        NULL
    );

    ActionParams *p = (ActionParams*)malloc(sizeof(ActionParams));
    p->hide = hide;
    p->crypt = crypt;

    g_signal_connect(dialog, "response",
        G_CALLBACK(on_folder_response), p);

    gtk_window_present(GTK_WINDOW(dialog));
}

/* =====================================================
   PASSWORD DIALOG RESPONSE
===================================================== */
void on_password_response(GtkDialog *dialog, int response, gpointer data) {
    if (response == GTK_RESPONSE_OK) {
        const char *pwd = gtk_editable_get_text(GTK_EDITABLE(password_entry));
        if (!strcmp(pwd, PASSWORD))
            choose_folder(1, 1);
        else
            show_message_dialog("Erreur", "Mot de passe incorrect");
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
}

void on_encrypt(GtkWidget *w, gpointer d) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "Mot de passe",
        main_window,
        GTK_DIALOG_MODAL,
        "OK", GTK_RESPONSE_OK,
        "Annuler", GTK_RESPONSE_CANCEL,
        NULL
    );

    password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Entrez le mot de passe");

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_box_append(GTK_BOX(content), password_entry);
    gtk_widget_set_margin_start(password_entry, 10);
    gtk_widget_set_margin_end(password_entry, 10);
    gtk_widget_set_margin_top(password_entry, 10);
    gtk_widget_set_margin_bottom(password_entry, 10);

    g_signal_connect(dialog, "response", G_CALLBACK(on_password_response), NULL);
    gtk_window_present(GTK_WINDOW(dialog));
}

/* =====================================================
   AUTO MODE FOLDER RESPONSE
===================================================== */
void on_auto_folder_response(GtkDialog *dialog, int response, gpointer data) {
    if (response == GTK_RESPONSE_ACCEPT) {
        GFile *file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        char *folder = g_file_get_path(file);

        strcpy(app_data.target_folder, folder);
        app_data.usb_count = get_usb_count();

        char message[512];
        sprintf(message, "Mode automatique activé.\nSurveillance du dossier:\n%s", folder);
        show_message_dialog("Auto-mode", message);

        g_free(folder);
        g_object_unref(file);
    } else {
        app_data.auto_mode = FALSE;
        // Réinitialiser le bouton toggle
        GtkWidget *toggle_btn = (GtkWidget*)data;
        if (toggle_btn) {
            gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(toggle_btn), FALSE);
        }
    }
    gtk_window_destroy(GTK_WINDOW(dialog));
}

/* =====================================================
   BUTTON CALLBACKS
===================================================== */
void on_decrypt(GtkWidget *w, gpointer d) {
    choose_folder(0, 0);
}

void on_hide(GtkWidget *w, gpointer d) {
    choose_folder(1, -1);
}

void on_show(GtkWidget *w, gpointer d) {
    choose_folder(0, -1);
}

void on_toggle_auto(GtkWidget *w, gpointer d) {
    GtkToggleButton *btn = GTK_TOGGLE_BUTTON(w);
    app_data.auto_mode = gtk_toggle_button_get_active(btn);

    if (app_data.auto_mode) {
        GtkWidget *dialog = gtk_file_chooser_dialog_new(
            "Dossier pour auto-mode",
            main_window,
            GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
            "Annuler", GTK_RESPONSE_CANCEL,
            "OK", GTK_RESPONSE_ACCEPT,
            NULL
        );

        g_signal_connect(dialog, "response", G_CALLBACK(on_auto_folder_response), w);
        gtk_window_present(GTK_WINDOW(dialog));
    } else {
        app_data.target_folder[0] = '\0';
        show_message_dialog("Auto-mode", "Mode automatique désactivé");
    }
}

/* =====================================================
   LOAD CSS - THEME NOIR/JAUNE
===================================================== */
void load_css() {
    GtkCssProvider *css = gtk_css_provider_new();
    const gchar *css_data =
        "* {\n"
        "  background-color: #0a0a0a;\n"
        "  color: #ffffff;\n"
        "}\n"
        "window {\n"
        "  background: linear-gradient(135deg, #0a0a0a, #1a1a1a);\n"
        "}\n"
        ".splash {\n"
        "  background: linear-gradient(135deg, #000000, #1a1a1a);\n"
        "  border: 3px solid #b8860b;\n"
        "  border-radius: 15px;\n"
        "}\n"
        "button {\n"
        "  background: linear-gradient(to bottom, #2a2a2a, #1a1a1a);\n"
        "  color: #ffffff;\n"
        "  border: 2px solid #b8860b;\n"
        "  border-radius: 8px;\n"
        "  padding: 15px;\n"
        "  margin: 8px;\n"
        "  font-weight: bold;\n"
        "  font-size: 14px;\n"
        "  min-width: 200px;\n"
        "}\n"
        "button:hover {\n"
        "  background: linear-gradient(to bottom, #3a3a3a, #2a2a2a);\n"
        "  color: #b8860b;\n"
        "  border-color: #ffd700;\n"
        "}\n"
        "label {\n"
        "  color: #b8860b;\n"
        "  font-weight: bold;\n"
        "}\n"
        ".title {\n"
        "  font-size: 28px;\n"
        "  color: #ffd700;\n"
        "}\n"
        ".subtitle {\n"
        "  font-size: 18px;\n"
        "  color: #b8860b;\n"
        "}\n"
        "entry {\n"
        "  background-color: #2a2a2a;\n"
        "  color: #ffffff;\n"
        "  border: 2px solid #b8860b;\n"
        "  border-radius: 5px;\n"
        "  padding: 10px;\n"
        "  font-size: 14px;\n"
        "}\n"
        "dialog {\n"
        "  background-color: #0a0a0a;\n"
        "}\n"
        "dialog > box {\n"
        "  background-color: #1a1a1a;\n"
        "  padding: 25px;\n"
        "  border: 3px solid #b8860b;\n"
        "  border-radius: 10px;\n"
        "}\n"
        "togglebutton {\n"
        "  background: linear-gradient(to bottom, #2a2a2a, #1a1a1a);\n"
        "  color: #ffffff;\n"
        "  border: 2px solid #b8860b;\n"
        "  border-radius: 8px;\n"
        "  padding: 12px;\n"
        "  margin: 10px;\n"
        "  min-width: 250px;\n"
        "}\n"
        "togglebutton:checked {\n"
        "  background: linear-gradient(to bottom, #b8860b, #8b6508);\n"
        "  color: #000000;\n"
        "  font-weight: bold;\n"
        "}\n"
        "separator {\n"
        "  background-color: #b8860b;\n"
        "  margin: 20px 0;\n"
        "  min-height: 2px;\n"
        "}\n";

    gtk_css_provider_load_from_data(css, css_data, -1);

    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(),
        GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
}

/* =====================================================
   TIMER FOR USB CHECK
===================================================== */
gboolean check_usb_timer(gpointer data) {
    check_auto_mode();
    return G_SOURCE_CONTINUE;
}

/* =====================================================
   UPDATE USB LABEL
===================================================== */
void update_usb_label(GtkLabel *label) {
    int current_usb = get_usb_count();
    char usb_info[100];
    sprintf(usb_info, "📱 USB connectés: <span foreground='#b8860b'><b>%d/%d</b></span>",
            current_usb, USB_NEEDED);
    gtk_label_set_markup(label, usb_info);
}

/* =====================================================
   USB UPDATE TIMER
===================================================== */
gboolean update_usb_timer(gpointer data) {
    if (data) {
        update_usb_label(GTK_LABEL(data));
    }
    return G_SOURCE_CONTINUE;
}

/* =====================================================
   MAIN WINDOW
===================================================== */
void show_main_window(GtkApplication *app) {
    main_window = GTK_WINDOW(gtk_application_window_new(app));
    gtk_window_set_title(main_window, "Projet Groupe1 - Sécurité Fichiers");
    gtk_window_set_default_size(main_window, 550, 500);
    gtk_window_set_resizable(main_window, FALSE);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_margin_start(main_box, 25);
    gtk_widget_set_margin_end(main_box, 25);
    gtk_widget_set_margin_top(main_box, 25);
    gtk_widget_set_margin_bottom(main_box, 25);

    // Titre
    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new("🔐 SÉCURITÉ FICHIERS");
    gtk_widget_add_css_class(title, "title");
    gtk_box_append(GTK_BOX(title_box), title);

    GtkWidget *subtitle = gtk_label_new("Projet Éducatif Groupe 1");
    gtk_widget_add_css_class(subtitle, "subtitle");
    gtk_box_append(GTK_BOX(title_box), subtitle);

    gtk_box_append(GTK_BOX(main_box), title_box);

    // Séparateur
    GtkWidget *sep1 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(GTK_BOX(main_box), sep1);

    // Mode automatique
    GtkWidget *auto_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *auto_label = gtk_label_new("Mode automatique USB:");
    gtk_widget_add_css_class(auto_label, "subtitle");
    gtk_box_append(GTK_BOX(auto_box), auto_label);

    GtkWidget *auto_btn = gtk_toggle_button_new_with_label("🚀 Activer Surveillance USB");
    g_signal_connect(auto_btn, "toggled", G_CALLBACK(on_toggle_auto), NULL);
    gtk_box_append(GTK_BOX(auto_box), auto_btn);

    gtk_box_append(GTK_BOX(main_box), auto_box);

    // Séparateur
    GtkWidget *sep2 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(GTK_BOX(main_box), sep2);

    // Actions manuelles
    GtkWidget *actions_label = gtk_label_new("Actions manuelles:");
    gtk_widget_add_css_class(actions_label, "subtitle");
    gtk_box_append(GTK_BOX(main_box), actions_label);

    // Boutons d'action dans une grille
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_widget_set_margin_top(grid, 10);
    gtk_widget_set_margin_bottom(grid, 10);

    GtkWidget *b1 = gtk_button_new_with_label("👁️‍🗨️ Masquer");
    GtkWidget *b2 = gtk_button_new_with_label("👁️ Démasquer");
    GtkWidget *b3 = gtk_button_new_with_label("🔒 Crypter");
    GtkWidget *b4 = gtk_button_new_with_label("🔓 Décrypter");
    GtkWidget *b5 = gtk_button_new_with_label("❌ Quitter");

    gtk_grid_attach(GTK_GRID(grid), b1, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), b2, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), b3, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), b4, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), b5, 0, 2, 2, 1);

    g_signal_connect(b1, "clicked", G_CALLBACK(on_hide), NULL);
    g_signal_connect(b2, "clicked", G_CALLBACK(on_show), NULL);
    g_signal_connect(b3, "clicked", G_CALLBACK(on_encrypt), NULL);
    g_signal_connect(b4, "clicked", G_CALLBACK(on_decrypt), NULL);
    g_signal_connect_swapped(b5, "clicked", G_CALLBACK(gtk_window_destroy), main_window);

    gtk_box_append(GTK_BOX(main_box), grid);

    // Séparateur
    GtkWidget *sep3 = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_append(GTK_BOX(main_box), sep3);

    // Info USB
    GtkWidget *usb_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *usb_label = gtk_label_new("");
    gtk_widget_add_css_class(usb_label, "subtitle");
    update_usb_label(GTK_LABEL(usb_label));

    GtkWidget *info_label = gtk_label_new("Pour décrypter: branchez 3 USB dans n'importe quel ordre");
    gtk_label_set_wrap(GTK_LABEL(info_label), TRUE);
    gtk_widget_set_margin_top(info_label, 5);

    gtk_box_append(GTK_BOX(usb_box), usb_label);
    gtk_box_append(GTK_BOX(usb_box), info_label);
    gtk_box_append(GTK_BOX(main_box), usb_box);

    gtk_window_set_child(main_window, main_box);
    gtk_window_present(main_window);

    // Démarrer les timers
    g_timeout_add_seconds(2, check_usb_timer, NULL);
    g_timeout_add_seconds(1, update_usb_timer, usb_label);
}

/* =====================================================
   SPLASH SCREEN
===================================================== */
void on_continue(GtkWidget *w, gpointer app) {
    gtk_window_destroy(GTK_WINDOW(gtk_widget_get_root(w)));
    show_main_window(GTK_APPLICATION(app));
}

void activate(GtkApplication *app) {
    load_css();

    GtkWidget *win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(win), "Projet Groupe1 - Démarrage");
    gtk_window_set_default_size(GTK_WINDOW(win), 450, 350);
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
    gtk_window_set_decorated(GTK_WINDOW(win), TRUE);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 30);
    gtk_widget_add_css_class(main_box, "splash");
    gtk_widget_set_margin_start(main_box, 40);
    gtk_widget_set_margin_end(main_box, 40);
    gtk_widget_set_margin_top(main_box, 40);
    gtk_widget_set_margin_bottom(main_box, 40);
    gtk_widget_set_halign(main_box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(main_box, GTK_ALIGN_CENTER);

    // Logo/Icon
    GtkWidget *icon_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *icon_label = gtk_label_new("🔐");
    gtk_widget_add_css_class(icon_label, "title");

    gtk_box_append(GTK_BOX(icon_box), icon_label);
    gtk_box_append(GTK_BOX(main_box), icon_box);

    // Titre
    GtkWidget *title_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *title = gtk_label_new("PROJET GROUPE 1");
    gtk_widget_add_css_class(title, "title");

    GtkWidget *subtitle = gtk_label_new("Système de Sécurité Fichiers");
    gtk_widget_add_css_class(subtitle, "subtitle");

    gtk_box_append(GTK_BOX(title_box), title);
    gtk_box_append(GTK_BOX(title_box), subtitle);
    gtk_box_append(GTK_BOX(main_box), title_box);

    // Message d'avertissement
    GtkWidget *warning_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *warning = gtk_label_new("⚠️ PROJET ÉDUCATIF UNIQUEMENT ⚠️");
    gtk_label_set_wrap(GTK_LABEL(warning), TRUE);

    GtkWidget *warning_text = gtk_label_new("Ce logiciel est destiné à l'apprentissage académique.\nUtilisez-le avec prudence dans un environnement contrôlé.");
    gtk_label_set_wrap(GTK_LABEL(warning_text), TRUE);
    gtk_widget_set_margin_top(warning_text, 5);

    gtk_box_append(GTK_BOX(warning_box), warning);
    gtk_box_append(GTK_BOX(warning_box), warning_text);
    gtk_box_append(GTK_BOX(main_box), warning_box);

    // Bouton continuer
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *btn = gtk_button_new_with_label("🚀 DÉMARRER L'APPLICATION");
    gtk_widget_set_margin_top(btn, 20);
    gtk_widget_set_size_request(btn, 250, 50);

    g_signal_connect(btn, "clicked", G_CALLBACK(on_continue), app);

    gtk_box_append(GTK_BOX(btn_box), btn);
    gtk_box_append(GTK_BOX(main_box), btn_box);

    gtk_window_set_child(GTK_WINDOW(win), main_box);
    gtk_window_present(GTK_WINDOW(win));
}

/* =====================================================
   MAIN
===================================================== */
int main(int argc, char **argv) {
    GtkApplication *app = gtk_application_new("com.groupe1.projet", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

    int status = g_application_run(G_APPLICATION(app), argc, argv);

    g_object_unref(app);
    return status;
}
