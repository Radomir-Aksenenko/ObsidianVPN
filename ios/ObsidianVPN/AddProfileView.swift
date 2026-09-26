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
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(.ultraThinMaterial.opacity(0.65))
                    )

                    Section {
                        TextEditor(text: $key)
                            .font(.system(.callout, design: .monospaced))
                            .frame(minHeight: 110)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .accessibilityLabel("Ключ доступа")
                            .onChange(of: key) { _, newValue in
                                autoDetectName(from: newValue)
                            }

                        HStack(spacing: 12) {
                            Button {
                                showScanner = true
                            } label: {
                                Label("QR-сканер", systemImage: "qrcode.viewfinder")
                                    .font(.system(.subheadline, design: .rounded, weight: .semibold))
                            }
                            .buttonStyle(.bordered)
                            .tint(ObsidianTheme.accent)

                            Button {
                                if let pasted = UIPasteboard.general.string {
                                    key = pasted
                                    autoDetectName(from: pasted)
                                }
                            } label: {
                                Label("Вставить", systemImage: "doc.on.clipboard")
                                    .font(.system(.subheadline, design: .rounded, weight: .semibold))
                            }
                            .buttonStyle(.bordered)
                            .tint(Color.white.opacity(0.85))
                        }
                        .padding(.vertical, 4)
                    } header: {
                        Text("Ключ доступа")
                    } footer: {
                        Text("Поддерживаются ссылки obsidian:// и vpn://, а также короткие ключи OBSDN-.")
                    }
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(.ultraThinMaterial.opacity(0.65))
                    )

                    if let errorMessage {
                        Section {
                            Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                                .font(.footnote)
                                .foregroundStyle(ObsidianTheme.danger)
                        }
                        .listRowBackground(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .fill(ObsidianTheme.danger.opacity(0.12))
                        )
                    }

                    Section {
                        Button {
                            save()
                        } label: {
                            Text("Сохранить сервер")
                                .font(.system(.body, design: .rounded, weight: .bold))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 4)
                        }
                        .disabled(key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .tint(ObsidianTheme.accent)
                    }
                    .listRowBackground(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? Color.white.opacity(0.04) : ObsidianTheme.accent.opacity(0.20))
                    )
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Новый сервер")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") { dismiss() }
                        .foregroundStyle(ObsidianTheme.secondaryText)
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
