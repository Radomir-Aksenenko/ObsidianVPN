import SwiftUI
import UIKit

struct AddProfileView: View {
    @EnvironmentObject private var profiles: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var key = ""
    @State private var errorMessage: String?
    @State private var showScanner = false

    var body: some View {
        NavigationStack {
            ZStack {
                MineralBackground()
                Form {
                    Section {
                        TextEditor(text: $key)
                            .font(.system(.callout, design: .monospaced))
                            .frame(minHeight: 132)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityLabel("Ключ доступа")

                        Button {
                            showScanner = true
                        } label: {
                            Label("Сканировать QR-код", systemImage: "qrcode.viewfinder")
                        }

                        Button {
                            if let pasted = UIPasteboard.general.string { key = pasted }
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
                    save()
                }
            }
        }
    }

    private func save() {
        do {
            profiles.add(try VPNProfile.imported(from: key))
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
