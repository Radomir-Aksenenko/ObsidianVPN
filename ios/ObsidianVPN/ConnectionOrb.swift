import SwiftUI

struct ConnectionOrb: View {
    let state: TunnelController.State
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var breathing = false

    private var isConnected: Bool { state == .connected }

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(.black.opacity(0.55))
                    .overlay {
                        Circle().fill(
                            RadialGradient(
                                colors: [
                                    (isConnected ? ObsidianTheme.accent : .white).opacity(0.14),
                                    .black.opacity(0.25),
                                    .black.opacity(0.8)
                                ],
                                center: .topLeading,
                                startRadius: 2,
                                endRadius: 180
                            )
                        )
                    }
                    .overlay {
                        Circle().stroke(
                            LinearGradient(
                                colors: [.white.opacity(0.24), .clear, .white.opacity(0.08)],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            ),
                            lineWidth: 1
                        )
                    }
                    .shadow(color: (isConnected ? ObsidianTheme.accent : .black).opacity(breathing ? 0.34 : 0.18), radius: breathing ? 34 : 18)

                Circle()
                    .trim(from: 0.04, to: state.isBusy ? 0.72 : 0.96)
                    .stroke(
                        isConnected ? ObsidianTheme.accent : Color.white.opacity(0.32),
                        style: StrokeStyle(lineWidth: 4, lineCap: .round)
                    )
                    .padding(10)
                    .rotationEffect(state.isBusy && !reduceMotion ? .degrees(breathing ? 360 : 0) : .zero)

                VStack(spacing: 14) {
                    Image(systemName: icon)
                        .font(.system(size: 34, weight: .light))
                    Text(actionLabel)
                        .font(.system(.headline, design: .rounded, weight: .semibold))
                }
                .foregroundStyle(isConnected ? ObsidianTheme.accent : ObsidianTheme.primaryText)
            }
            .frame(width: 222, height: 222)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(actionLabel)
        .accessibilityHint(isConnected ? "Отключает VPN" : "Подключает VPN")
        .onAppear { animate() }
        .onChange(of: state) { _, _ in animate() }
    }

    private var actionLabel: String {
        switch state {
        case .disconnected, .failed: "Подключить"
        case .preparing: "Отмена"
        case .connected: "Отключить"
        case .disconnecting: "Отключение"
        }
    }

    private var icon: String {
        switch state {
        case .preparing, .disconnecting: "ellipsis"
        case .connected: "lock.fill"
        case .disconnected, .failed: "power"
        }
    }

    private func animate() {
        guard !reduceMotion else { return }
        breathing = false
        withAnimation(.easeInOut(duration: state.isBusy ? 1.1 : 2.4).repeatForever(autoreverses: !state.isBusy)) {
            breathing = true
        }
    }
}
