import SwiftUI
import UIKit

// MARK: - Obsidian Apple Design System

enum ObsidianTheme {
    // Deep Obsidian Glass Backgrounds
    static let background = Color(red: 0.04, green: 0.045, blue: 0.052)
    static let deepBlack = Color(red: 0.02, green: 0.022, blue: 0.025)
    static let surface = Color(red: 0.08, green: 0.09, blue: 0.10)
    static let surfaceSecondary = Color(red: 0.11, green: 0.125, blue: 0.14)
    static let raised = Color(red: 0.14, green: 0.155, blue: 0.17)

    // Apple Emerald / Cyan Liquid Iridescent Palette
    static let accent = Color(red: 0.20, green: 0.88, blue: 0.58)
    static let accentCyan = Color(red: 0.18, green: 0.82, blue: 0.94)
    static let accentMuted = Color(red: 0.10, green: 0.26, blue: 0.19)
    static let amber = Color(red: 1.0, green: 0.70, blue: 0.22)
    static let amberMuted = Color(red: 0.28, green: 0.20, blue: 0.08)
    static let danger = Color(red: 1.0, green: 0.35, blue: 0.35)

    // Native Apple Typography Hierarchy
    static let primaryText = Color.white
    static let secondaryText = Color.white.opacity(0.68)
    static let tertiaryText = Color.white.opacity(0.42)
    static let quaternaryText = Color.white.opacity(0.24)

    // Glass & Optical Caustic Hairlines
    static let glassBorder = Color.white.opacity(0.14)
    static let glassBorderProminent = Color.white.opacity(0.26)
    static let glassInnerGleam = Color.white.opacity(0.18)
    static let specularHighlight = Color.white.opacity(0.45)

    // Chromatic Dispersion (Prismatic Glass Rim)
    static let chromaticGradient = AngularGradient(
        colors: [
            Color.white.opacity(0.40),
            Color(red: 0.3, green: 0.8, blue: 1.0).opacity(0.35),
            Color(red: 0.4, green: 1.0, blue: 0.7).opacity(0.30),
            Color(red: 1.0, green: 0.85, blue: 0.3).opacity(0.25),
            Color(red: 0.9, green: 0.4, blue: 0.9).opacity(0.32),
            Color.white.opacity(0.40)
        ],
        center: .center
    )
}

// MARK: - Fluid Animation Presets (Apple Spring Timing)

extension Animation {
    /// Natural organic fluid spring with small overshoot
    static let fluidSpring = Animation.spring(response: 0.42, dampingFraction: 0.72)

    /// Responsive tactile spring for interactive bubble press
    static let fluidTactile = Animation.spring(response: 0.34, dampingFraction: 0.62)

    /// Bouncy spring for icons and state confirmations
    static let fluidBouncy = Animation.spring(response: 0.48, dampingFraction: 0.58)

    /// Smooth non-bouncing transition for layout changes
    static let fluidSmooth = Animation.smooth(duration: 0.35)
}

// MARK: - Apple Mineral Glass Ambient Background

struct MineralBackground: View {
    @State private var ambientPhase: Double = 0

    var body: some View {
        ZStack {
            ObsidianTheme.background

            // Top-center refractive caustic bloom
            RadialGradient(
                colors: [
                    Color(red: 0.08, green: 0.24, blue: 0.18).opacity(0.48),
                    Color(red: 0.05, green: 0.14, blue: 0.12).opacity(0.20),
                    .clear
                ],
                center: UnitPoint(x: 0.50, y: 0.20),
                startRadius: 20,
                endRadius: 460
            )

            // Bottom-right cyan ambient light bounce
            RadialGradient(
                colors: [
                    Color(red: 0.06, green: 0.18, blue: 0.26).opacity(0.38),
                    Color(red: 0.04, green: 0.10, blue: 0.16).opacity(0.15),
                    .clear
                ],
                center: UnitPoint(x: 0.88, y: 0.78),
                startRadius: 30,
                endRadius: 520
            )

            // Deep vignette
            LinearGradient(
                colors: [
                    Color.black.opacity(0.45),
                    Color.clear,
                    Color.black.opacity(0.75)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
        }
        .ignoresSafeArea()
    }
}

// MARK: - Apple Liquid Glass Card Modifier

struct AppleGlassCardModifier: ViewModifier {
    var cornerRadius: CGFloat = 22
    var highlightOpacity: Double = 0.22
    var interactive: Bool = false

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(.ultraThinMaterial)
            )
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color.white.opacity(0.025))
            )
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(highlightOpacity),
                                Color.white.opacity(0.06),
                                Color.white.opacity(0.01),
                                Color.white.opacity(0.09)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            }
            .shadow(color: Color.black.opacity(0.40), radius: 18, x: 0, y: 8)
    }
}

// MARK: - View Extensions

extension View {
    func appleGlassCard(cornerRadius: CGFloat = 22, highlight: Double = 0.22, interactive: Bool = false) -> some View {
        modifier(AppleGlassCardModifier(cornerRadius: cornerRadius, highlightOpacity: highlight, interactive: interactive))
    }

    func obsidianCard() -> some View {
        appleGlassCard(cornerRadius: 22, highlight: 0.20)
    }
}
