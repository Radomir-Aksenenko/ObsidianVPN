import SwiftUI
import UIKit

// MARK: - Organic Liquid Glass Bubble Shape

/// An animatable organic liquid membrane that simulates dynamic surface tension
/// and fluid oscillations using harmonic trigonometric wave superposition.
struct LiquidBubbleShape: Shape {
    var phase: Double
    var amplitude: CGFloat

    var animatableData: AnimatablePair<Double, CGFloat> {
        get { AnimatablePair(phase, amplitude) }
        set {
            phase = newValue.first
            amplitude = newValue.second
        }
    }

    func path(in rect: CGRect) -> Path {
        let center = CGPoint(x: rect.midX, y: rect.midY)
        let baseRadius = min(rect.width, rect.height) / 2.0
        let pointsCount = 72
        var path = Path()

        guard baseRadius > 10 else { return path }

        var points: [CGPoint] = []
        points.reserveCapacity(pointsCount)

        for i in 0..<pointsCount {
            let angle = (Double(i) / Double(pointsCount)) * 2.0 * .pi
            // Superposition of 3 harmonic wave frequencies for natural organic fluidity
            let wave1 = sin(angle * 3.0 + phase) * amplitude
            let wave2 = cos(angle * 2.0 - phase * 0.8) * (amplitude * 0.65)
            let wave3 = sin(angle * 4.0 + phase * 1.4) * (amplitude * 0.35)
            let r = baseRadius + CGFloat(wave1 + wave2 + wave3)

            let x = center.x + r * CGFloat(cos(angle))
            let y = center.y + r * CGFloat(sin(angle))
            points.append(CGPoint(x: x, y: y))
        }

        guard let first = points.first else { return path }
        path.move(to: first)

        // Smooth Cardinal/Catmull-Rom spline around the points
        for i in 0..<pointsCount {
            let p0 = points[(i - 1 + pointsCount) % pointsCount]
            let p1 = points[i]
            let p2 = points[(i + 1) % pointsCount]
            let p3 = points[(i + 2) % pointsCount]

            // Approximate smooth cubic Bezier segment
            let c1 = CGPoint(
                x: p1.x + (p2.x - p0.x) / 6.0,
                y: p1.y + (p2.y - p0.y) / 6.0
            )
            let c2 = CGPoint(
                x: p2.x - (p3.x - p1.x) / 6.0,
                y: p2.y - (p3.y - p1.y) / 6.0
            )
            path.addCurve(to: p2, control1: c1, control2: c2)
        }

        path.closeSubpath()
        return path
    }
}

// MARK: - Enormous Liquid Glass Connection Orb

struct ConnectionOrb: View {
    let state: TunnelController.State
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    // Harmonic Fluid Wobble State
    @State private var fluidPhase: Double = 0
    @State private var fluidAmplitude: CGFloat = 3.2

    // Optical & Vortex States
    @State private var vortexRotation: Double = 0
    @State private var causticPulse: CGFloat = 1.0
    @State private var shockwaveScale: CGFloat = 1.0
    @State private var shockwaveOpacity: Double = 0.0

    // Interactive Tactile Physics States
    @State private var isTouching: Bool = false
    @State private var dragOffset: CGSize = .zero
    @State private var squishX: CGFloat = 1.0
    @State private var squishY: CGFloat = 1.0

    private var isConnected: Bool { state == .connected }
    private var isBusy: Bool { state.isBusy }

    // Dimensions
    private let bubbleSize: CGFloat = 248.0

    var body: some View {
        Button {
            triggerTapHaptic()
            action()
        } label: {
            ZStack {
                // 1. Deep Caustic Refraction Glow (Behind the bubble)
                ambientCausticAura

                // 2. Concentric Shockwave Pulse Rings (Liquid ripple waves)
                if (isConnected || isBusy) && !reduceMotion {
                    LiquidBubbleShape(phase: fluidPhase * 0.7, amplitude: fluidAmplitude * 1.5)
                        .stroke(activeThemeColor.opacity(0.35), lineWidth: 2.2)
                        .frame(width: bubbleSize + 16, height: bubbleSize + 16)
                        .scaleEffect(shockwaveScale)
                        .opacity(shockwaveOpacity)
                }

                // 3. The Enormous Liquid Glass Membrane
                ZStack {
                    // Layer A: Deep Refractive Fluid Core
                    LiquidBubbleShape(phase: fluidPhase, amplitude: reduceMotion ? 0 : fluidAmplitude)
                        .fill(liquidCoreGradient)
                        .frame(width: bubbleSize, height: bubbleSize)
                        .shadow(color: activeThemeColor.opacity(isConnected ? 0.38 : (isBusy ? 0.28 : 0.08)), radius: 32, y: 12)

                    // Layer B: Subsurface Vortex Currents (Active Swirl)
                    if (isBusy || isConnected) && !reduceMotion {
                        LiquidBubbleShape(phase: fluidPhase * 1.2, amplitude: fluidAmplitude)
                            .fill(subsurfaceVortexGradient)
                            .frame(width: bubbleSize - 6, height: bubbleSize - 6)
                            .rotationEffect(.degrees(vortexRotation))
                            .blur(radius: isBusy ? 14 : 22)
                            .opacity(isBusy ? 0.85 : 0.40)
                            .blendMode(.screen)
                    }

                    // Layer C: Ultra-Thin Optical Glass Frosting
                    LiquidBubbleShape(phase: fluidPhase, amplitude: reduceMotion ? 0 : fluidAmplitude)
                        .fill(.ultraThinMaterial)
                        .frame(width: bubbleSize - 4, height: bubbleSize - 4)
                        .overlay {
                            // Internal radial refraction gleam
                            Circle()
                                .fill(internalGleamGradient)
                                .frame(width: bubbleSize - 8, height: bubbleSize - 8)
                        }

                    // Layer D: Chromatic Dispersion Rim (Prismatic Boundary)
                    LiquidBubbleShape(phase: fluidPhase, amplitude: reduceMotion ? 0 : fluidAmplitude)
                        .stroke(ObsidianTheme.chromaticGradient, lineWidth: 1.8)
                        .frame(width: bubbleSize - 2, height: bubbleSize - 2)

                    // Layer E: Secondary Glowing Progress/Status Ring
                    Circle()
                        .trim(from: 0.03, to: isBusy ? 0.82 : 0.97)
                        .stroke(
                            activeRingStrokeStyle,
                            style: StrokeStyle(lineWidth: 3.5, lineCap: .round)
                        )
                        .frame(width: bubbleSize - 32, height: bubbleSize - 32)
                        .rotationEffect(.degrees(isBusy ? vortexRotation : 0))

                    // Layer F: Convex Specular Glare (Top-Left Overhead Glint)
                    glassConvexSpecularHighlight

                    // Layer G: Secondary Bottom Bounce Highlight (Ground Refraction)
                    glassBottomBounceHighlight

                    // Layer H: Core Interactive Content (Icon & Typography)
                    bubbleCenterContent
                }
                .frame(width: bubbleSize, height: bubbleSize)
                // Interactive squish & elastic rebound physics
                .scaleEffect(x: isTouching ? 0.94 * squishX : causticPulse,
                             y: isTouching ? 0.94 * squishY : causticPulse)
                .offset(dragOffset)
                .animation(.fluidTactile, value: isTouching)
                .animation(.fluidSpring, value: dragOffset)
                .animation(.easeInOut(duration: isBusy ? 1.0 : 2.6).repeatForever(autoreverses: true), value: causticPulse)
            }
            .frame(width: bubbleSize + 48, height: bubbleSize + 48)
            .contentShape(Circle())
        }
        .buttonStyle(TactileBubbleButtonStyle(
            isTouching: $isTouching,
            dragOffset: $dragOffset,
            squishX: $squishX,
            squishY: $squishY
        ))
        .onAppear {
            startFluidSimulation()
        }
        .onChange(of: state) { _, _ in
            startFluidSimulation()
        }
        .accessibilityLabel(actionTitle)
        .accessibilityHint(isConnected ? "Отключает защиту VPN" : "Активирует защиту VPN")
    }

    // MARK: - Optical Subviews & Caustics

    /// Multi-stop ambient caustic bloom that casts light onto the app background
    private var ambientCausticAura: some View {
        Circle()
            .fill(
                RadialGradient(
                    colors: [
                        activeThemeColor.opacity(isConnected ? 0.36 : (isBusy ? 0.30 : 0.09)),
                        activeThemeColor.opacity(isConnected ? 0.16 : 0.03),
                        Color.clear
                    ],
                    center: .center,
                    startRadius: 30,
                    endRadius: 155
                )
            )
            .frame(width: bubbleSize + 64, height: bubbleSize + 64)
            .blur(radius: 28)
            .allowsHitTesting(false)
    }

    /// Deep gradient for the refractive fluid interior
    private var liquidCoreGradient: some ShapeStyle {
        RadialGradient(
            colors: [
                (isConnected ? Color(red: 0.08, green: 0.28, blue: 0.20) :
                    (isBusy ? Color(red: 0.26, green: 0.18, blue: 0.08) : Color(red: 0.11, green: 0.13, blue: 0.15))).opacity(0.92),
                Color.black.opacity(0.96)
            ],
            center: UnitPoint(x: 0.35, y: 0.30),
            startRadius: 20,
            endRadius: 170
        )
    }

    /// Swirling liquid current gradient visible during connection or active state
    private var subsurfaceVortexGradient: some ShapeStyle {
        AngularGradient(
            colors: [
                ObsidianTheme.accent.opacity(0.85),
                ObsidianTheme.accentCyan.opacity(0.70),
                ObsidianTheme.amber.opacity(0.75),
                ObsidianTheme.accent.opacity(0.20),
                ObsidianTheme.accent.opacity(0.85)
            ],
            center: .center
        )
    }

    /// Inner radial refraction gleam simulating light entering through the convex lens
    private var internalGleamGradient: some ShapeStyle {
        RadialGradient(
            colors: [
                Color.white.opacity(0.24),
                activeThemeColor.opacity(isConnected ? 0.28 : 0.07),
                Color.clear
            ],
            center: UnitPoint(x: 0.30, y: 0.26),
            startRadius: 8,
            endRadius: 125
        )
    }

    /// Active state indicator ring style
    private var activeRingStrokeStyle: some ShapeStyle {
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
                    colors: [
                        ObsidianTheme.amber,
                        ObsidianTheme.accent,
                        ObsidianTheme.accentCyan,
                        ObsidianTheme.amber
                    ],
                    center: .center
                )
            )
        } else {
            return AnyShapeStyle(
                LinearGradient(
                    colors: [Color.white.opacity(0.40), Color.white.opacity(0.08)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
        }
    }

    /// Convex specular highlight (simulates Apple glass lens reflection)
    private var glassConvexSpecularHighlight: some View {
        VStack {
            HStack {
                Ellipse()
                    .fill(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(0.68),
                                Color.white.opacity(0.25),
                                Color.clear
                            ],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .frame(width: 104, height: 48)
                    .rotationEffect(.degrees(-28))
                    .blur(radius: 1.5)
                    .padding(.top, 18)
                    .padding(.leading, 26)
                Spacer()
            }
            Spacer()
        }
        .allowsHitTesting(false)
    }

    /// Secondary bottom bounce highlight (simulates ground plane reflection on glass)
    private var glassBottomBounceHighlight: some View {
        VStack {
            Spacer()
            Capsule()
                .fill(
                    LinearGradient(
                        colors: [
                            Color.clear,
                            (isConnected ? ObsidianTheme.accentCyan : Color.white).opacity(0.22),
                            Color.clear
                        ],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
                .frame(width: 110, height: 3.5)
                .blur(radius: 0.8)
                .padding(.bottom, 18)
        }
        .allowsHitTesting(false)
    }

    /// Center interactive content inside the bubble
    private var bubbleCenterContent: some View {
        VStack(spacing: 11) {
            // Hero SF Symbol with dynamic iOS effects
            Image(systemName: iconName)
                .font(.system(size: 42, weight: .medium, design: .rounded))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(iconColor)
                .shadow(color: activeThemeColor.opacity(isConnected ? 0.70 : 0.0), radius: 14)
                .symbolEffect(.pulse, options: .repeating, isActive: isBusy)
                .contentTransition(.symbolEffect(.replace))

            VStack(spacing: 3) {
                Text(actionTitle)
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(ObsidianTheme.primaryText)
                    .tracking(0.6)

                HStack(spacing: 5) {
                    Circle()
                        .fill(pillDotColor)
                        .frame(width: 5.5, height: 5.5)
                        .shadow(color: pillDotColor.opacity(0.8), radius: 3)

                    Text(statusSubtitle)
                        .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                        .foregroundStyle(statusSubtitleColor)
                        .tracking(0.5)
                }
            }
        }
    }

    // MARK: - Dynamic State Helpers

    private var activeThemeColor: Color {
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
        return Color.white.opacity(0.88)
    }

    private var actionTitle: String {
        switch state {
        case .disconnected, .failed: return "ПОДКЛЮЧИТЬ"
        case .preparing: return "ОТМЕНА"
        case .connected: return "ОТКЛЮЧИТЬ"
        case .disconnecting: return "ОСТАНОВКА"
        }
    }

    private var statusSubtitle: String {
        switch state {
        case .disconnected, .failed: return "Obsidian Core"
        case .preparing: return "Шифрование..."
        case .connected: return "Защищено"
        case .disconnecting: return "Завершение"
        }
    }

    private var statusSubtitleColor: Color {
        if isConnected { return ObsidianTheme.accent.opacity(0.95) }
        if isBusy { return ObsidianTheme.amber.opacity(0.95) }
        return ObsidianTheme.secondaryText
    }

    private var pillDotColor: Color {
        if isConnected { return ObsidianTheme.accent }
        if isBusy { return ObsidianTheme.amber }
        return Color.white.opacity(0.40)
    }

    // MARK: - Animation & Physics Driver

    private func startFluidSimulation() {
        guard !reduceMotion else {
            fluidAmplitude = 0
            causticPulse = 1.0
            return
        }

        if isBusy {
            // Energetic fluid churning
            fluidAmplitude = 5.2
            withAnimation(.linear(duration: 1.8).repeatForever(autoreverses: false)) {
                vortexRotation = 360
            }
            withAnimation(.linear(duration: 3.2).repeatForever(autoreverses: false)) {
                fluidPhase = 2 * .pi
            }
            withAnimation(.easeInOut(duration: 0.75).repeatForever(autoreverses: true)) {
                causticPulse = 1.035
            }
        } else if isConnected {
            // Calm, radiant, living organic bubble
            fluidAmplitude = 3.6
            withAnimation(.linear(duration: 7.0).repeatForever(autoreverses: false)) {
                vortexRotation = 360
            }
            withAnimation(.linear(duration: 5.5).repeatForever(autoreverses: false)) {
                fluidPhase = 2 * .pi
            }
            withAnimation(.easeInOut(duration: 2.6).repeatForever(autoreverses: true)) {
                causticPulse = 1.025
            }
            // Trigger shockwave pulse on connect
            withAnimation(.easeOut(duration: 2.2).repeatForever(autoreverses: false)) {
                shockwaveScale = 1.48
                shockwaveOpacity = 0.0
            }
            shockwaveScale = 1.0
            shockwaveOpacity = 0.60
        } else {
            // Resting crystalline zero-gravity liquid bubble
            fluidAmplitude = 2.4
            vortexRotation = 0
            causticPulse = 1.0
            shockwaveScale = 1.0
            shockwaveOpacity = 0.0
            withAnimation(.linear(duration: 8.0).repeatForever(autoreverses: false)) {
                fluidPhase = 2 * .pi
            }
        }
    }

    private func triggerTapHaptic() {
        let generator = UIImpactFeedbackGenerator(style: isConnected ? .medium : .rigid)
        generator.prepare()
        generator.impactOccurred()
    }
}

// MARK: - Tactile Bubble Button Style with Fluid Squish Physics

private struct TactileBubbleButtonStyle: ButtonStyle {
    @Binding var isTouching: Bool
    @Binding var dragOffset: CGSize
    @Binding var squishX: CGFloat
    @Binding var squishY: CGFloat

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .onChange(of: configuration.isPressed) { _, newValue in
                withAnimation(.fluidTactile) {
                    isTouching = newValue
                    if newValue {
                        squishX = 1.04
                        squishY = 0.94
                    } else {
                        squishX = 1.0
                        squishY = 1.0
                        dragOffset = .zero
                    }
                }
            }
    }
}
