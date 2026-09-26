import SwiftUI
import UIKit

struct AddProfileView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var key = ""
    @State private var customName = ""
    @State private var errorMessage: String?
    @State private var showScanner = false

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()
                Form {
                    Section {
                        TextField("Название сервера (необязательно)", text: $customName)
                            .textInputAutocapitalization(.words)
                    } header: {
                        Text("Название")
                    } footer: {
                        Text("Если оставить пустым, имя определится автоматически из адреса сервера.")
                    }

                    Section {
                        TextEditor(text: $key)
                            .font(.system(.callout, design: .monospaced))
                            .frame(minHeight: 120)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityLabel("Ключ доступа")
                            .onChange(of: key) { newValue in
                                autoDetectName(from: newValue)
                            }

                        Button {
                            showScanner = true
                        } label: {
                            Label("Сканировать QR-код", systemImage: "qrcode.viewfinder")
                        }

                        Button {
                            if let pasted = UIPasteboard.general.string {
                                key = pasted
                                autoDetectName(from: pasted)
                            }
                        } label: {
                            Label("Вставить из буфера", systemImage: "doc.on.clipboard")
                        }
                    } header: {
                        Text("Ключ доступа")
                    } footer: {
                        Text("Поддерживаются ссылки obsidian:// и vpn://, а также короткие ключи OBSDN-.")
                    }

                    if let errorMessage {
                        Section {
                            Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(ObsidianTheme.danger)
                        }
                    }

                    Section {
                        Button("Сохранить сервер") { save() }
                            .frame(maxWidth: .infinity)
                            .disabled(key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Новый сервер")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") { dismiss() }
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerSheet { scannedCode in
                    key = scannedCode
                    autoDetectName(from: scannedCode)
                    save()
                }
            }
        }
    }

    private func autoDetectName(from raw: String) {
        guard customName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        if let parsed = ObsidianURIComponents.parse(raw) {
            if let frag = parsed.fragment, !frag.isEmpty {
                customName = frag
            } else if !parsed.endpoint.isEmpty {
                customName = parsed.endpoint
            }
        }
    }

    private func save() {
        do {
            let profile = try VPNProfile.imported(
                from: key,
                customName: customName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : customName
            )
            profiles.add(profile)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
