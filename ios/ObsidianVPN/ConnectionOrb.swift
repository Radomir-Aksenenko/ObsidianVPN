import SwiftUI
import UIKit

struct ConnectionOrb: View {
    let state: TunnelController.State
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var rotationAngle: Double = 0
    @State private var pulseScale: CGFloat = 1.0
    @State private var rippleScale: CGFloat = 1.0
    @State private var rippleOpacity: Double = 0.0
    @State private var isPressed: Bool = false

    private var isConnected: Bool { state == .connected }
    private var isBusy: Bool { state.isBusy }

    var body: some View {
        Button {
            triggerHaptic()
            action()
        } label: {
            ZStack {
                // 1. Ambient fluid caustic aura
                ambientGlow

                // 2. Liquid concentric pulse waves when connected or preparing
                if (isConnected || isBusy) && !reduceMotion {
                    Circle()
                        .stroke(activeAccentColor.opacity(0.35), lineWidth: 2)
                        .scaleEffect(rippleScale)
                        .opacity(rippleOpacity)
                        .frame(width: 220, height: 220)
                }

                // 3. Liquid Glass Lens Core
                ZStack {
                    // Deep refractive fluid base
                    Circle()
                        .fill(glassBaseFill)
                        .frame(width: 210, height: 210)

                    // Liquid vortex swirl when busy
                    if isBusy && !reduceMotion {
                        Circle()
                            .fill(
                                AngularGradient(
                                    colors: [
                                        ObsidianTheme.accent.opacity(0.8),
                                        ObsidianTheme.accentCyan.opacity(0.6),
                                        ObsidianTheme.amber.opacity(0.8),
                                        ObsidianTheme.accent.opacity(0.2),
                                        ObsidianTheme.accent.opacity(0.8)
                                    ],
                                    center: .center
                                )
                            )
                            .frame(width: 206, height: 206)
                            .blur(radius: 12)
                            .rotationEffect(.degrees(rotationAngle))
                            .mask(Circle().stroke(lineWidth: 18))
                    }

                    // Inner frosted glass refraction
                    Circle()
                        .fill(.ultraThinMaterial)
                        .frame(width: 206, height: 206)
                        .overlay {
                            Circle().fill(innerRadialGleam)
                        }

                    // Chromatic dispersion rim (optical dispersion ring)
                    Circle()
                        .stroke(
                            AngularGradient(
                                colors: [
                                    Color.white.opacity(0.45),
                                    Color.cyan.opacity(0.35),
                                    Color.green.opacity(0.3),
                                    Color.yellow.opacity(0.2),
                                    Color.purple.opacity(0.35),
                                    Color.white.opacity(0.45)
                                ],
                                center: .center
                            ),
                            lineWidth: 1.5
                        )
                        .frame(width: 208, height: 208)

                    // Secondary inner ring with progress/state indicator
                    Circle()
                        .trim(from: 0.05, to: isBusy ? 0.75 : 0.95)
                        .stroke(
                            activeRingGradient,
                            style: StrokeStyle(lineWidth: 3.5, lineCap: .round)
                        )
                        .frame(width: 186, height: 186)
                        .rotationEffect(.degrees(isBusy ? rotationAngle : 0))

                    // Polished convex glass specular reflection (Top-Left Glint)
                    glassSpecularHighlight

                    // Bottom surface bounce reflection
                    bottomGleamHighlight

                    // Center Interactive Content
                    centerContent
                }
                .frame(width: 210, height: 210)
                .scaleEffect(isPressed ? 0.94 : pulseScale)
                .animation(.spring(response: 0.35, dampingFraction: 0.65), value: isPressed)
                .animation(.easeInOut(duration: isBusy ? 1.0 : 2.4).repeatForever(autoreverses: true), value: pulseScale)
            }
            .frame(width: 250, height: 250)
            .contentShape(Circle())
        }
        .buttonStyle(LiquidGlassButtonStyle(isPressed: $isPressed))
        .onAppear { startAnimations() }
        .onChange(of: state) { _, _ in startAnimations() }
        .accessibilityLabel(actionLabel)
        .accessibilityHint(isConnected ? "Отключает защиту VPN" : "Активирует защиту VPN")
    }

    // MARK: - Subviews & Materials

    private var ambientGlow: some View {
        Circle()
            .fill(
                RadialGradient(
                    colors: [
                        activeAccentColor.opacity(isConnected ? 0.32 : (isBusy ? 0.28 : 0.08)),
                        activeAccentColor.opacity(0.0)
                    ],
                    center: .center,
                    startRadius: 40,
                    endRadius: 130
                )
            )
            .frame(width: 260, height: 260)
            .blur(radius: 20)
    }

    private var glassBaseFill: some ShapeStyle {
        RadialGradient(
            colors: [
                (isConnected ? ObsidianTheme.accentMuted : Color(red: 0.10, green: 0.12, blue: 0.13)).opacity(0.85),
                Color.black.opacity(0.92)
            ],
            center: .topLeading,
            startRadius: 20,
            endRadius: 180
        )
    }

    private var innerRadialGleam: some ShapeStyle {
        RadialGradient(
            colors: [
                Color.white.opacity(0.18),
                activeAccentColor.opacity(isConnected ? 0.22 : 0.05),
                .clear
            ],
            center: UnitPoint(x: 0.32, y: 0.28),
            startRadius: 4,
            endRadius: 110
        )
    }

    private var activeRingGradient: some ShapeStyle {
        if isConnected {
            return AnyShapeStyle(
                LinearGradient(
                    colors: [ObsidianTheme.accent, ObsidianTheme.accentCyan],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
        } else if isBusy {
            return AnyShapeStyle(
                AngularGradient(
                    colors: [ObsidianTheme.amber, ObsidianTheme.accent, ObsidianTheme.accentCyan, ObsidianTheme.amber],
                    center: .center
                )
            )
        } else {
            return AnyShapeStyle(
                LinearGradient(
                    colors: [Color.white.opacity(0.35), Color.white.opacity(0.08)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
        }
    }

    private var glassSpecularHighlight: some View {
        VStack {
            HStack {
                Ellipse()
                    .fill(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(0.55),
                                Color.white.opacity(0.20),
                                Color.clear
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .frame(width: 90, height: 42)
                    .rotationEffect(.degrees(-26))
                    .blur(radius: 1.2)
                    .padding(.top, 16)
                    .padding(.leading, 24)
                Spacer()
            }
            Spacer()
        }
        .allowsHitTesting(false)
    }

    private var bottomGleamHighlight: some View {
        VStack {
            Spacer()
            Capsule()
                .fill(
                    LinearGradient(
                        colors: [.clear, Color.white.opacity(0.14), .clear],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .frame(width: 96, height: 3)
                .padding(.bottom, 16)
        }
        .allowsHitTesting(false)
    }

    private var centerContent: some View {
        VStack(spacing: 10) {
            Image(systemName: iconName)
                .font(.system(size: 38, weight: .medium, design: .rounded))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(iconColor)
                .shadow(color: activeAccentColor.opacity(isConnected ? 0.65 : 0.0), radius: 10)

            VStack(spacing: 3) {
                Text(actionLabel)
                    .font(.system(size: 15, weight: .bold, design: .rounded))
                    .foregroundStyle(ObsidianTheme.primaryText)

                Text(statusPillText)
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .foregroundStyle(subtitleColor)
                    .tracking(0.6)
            }
        }
    }

    // MARK: - Helpers

    private var activeAccentColor: Color {
        if isConnected { return ObsidianTheme.accent }
        if isBusy { return ObsidianTheme.amber }
        return Color.white
    }

    private var iconName: String {
        switch state {
        case .connected: return "lock.shield.fill"
        case .preparing, .disconnecting: return "antenna.radiowaves.left.and.right"
        case .disconnected, .failed: return "power"
        }
    }

    private var iconColor: Color {
        if isConnected { return ObsidianTheme.accent }
        if isBusy { return ObsidianTheme.amber }
        return Color.white.opacity(0.85)
    }

    private var subtitleColor: Color {
        if isConnected { return ObsidianTheme.accent.opacity(0.9) }
        if isBusy { return ObsidianTheme.amber.opacity(0.9) }
        return ObsidianTheme.secondaryText
    }

    private var actionLabel: String {
        switch state {
        case .disconnected, .failed: "ПОДКЛЮЧИТЬ"
        case .preparing: "ОТМЕНА"
        case .connected: "ОТКЛЮЧИТЬ"
        case .disconnecting: "ОСТАНОВКА"
        }
    }

    private var statusPillText: String {
        switch state {
        case .disconnected, .failed: "Obsidian Core"
        case .preparing: "Шифрование..."
        case .connected: "Защищено"
        case .disconnecting: "Завершение"
        }
    }

    private func triggerHaptic() {
        let generator = UIImpactFeedbackGenerator(style: isConnected ? .medium : .rigid)
        generator.prepare()
        generator.impactOccurred()
    }

    private func startAnimations() {
        guard !reduceMotion else { return }

        if isBusy {
            withAnimation(.linear(duration: 2.2).repeatForever(autoreverses: false)) {
                rotationAngle = 360
            }
            withAnimation(.easeInOut(duration: 0.8).repeatForever(autoreverses: true)) {
                pulseScale = 1.03
            }
        } else if isConnected {
            withAnimation(.easeInOut(duration: 2.8).repeatForever(autoreverses: true)) {
                pulseScale = 1.02
            }
            withAnimation(.easeOut(duration: 2.0).repeatForever(autoreverses: false)) {
                rippleScale = 1.45
                rippleOpacity = 0.0
            }
            rippleScale = 1.0
            rippleOpacity = 0.55
        } else {
            pulseScale = 1.0
            rotationAngle = 0
            rippleScale = 1.0
            rippleOpacity = 0.0
        }
    }
}

// MARK: - Button Style with Spring Compression

private struct LiquidGlassButtonStyle: ButtonStyle {
    @Binding var isPressed: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .onChange(of: configuration.isPressed) { newValue in
                isPressed = newValue
            }
    }
}
