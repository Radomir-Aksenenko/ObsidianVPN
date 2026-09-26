import SwiftUI

enum ObsidianTheme {
    static let background = Color(red: 0.04, green: 0.045, blue: 0.048)
    static let deepBlack = Color.black
    static let surface = Color(red: 0.08, green: 0.09, blue: 0.095)
    static let raised = Color(red: 0.12, green: 0.13, blue: 0.14)

    // Apple Emerald / Cyan iridescent palette
    static let accent = Color(red: 0.22, green: 0.88, blue: 0.54)
    static let accentCyan = Color(red: 0.20, green: 0.80, blue: 0.92)
    static let accentMuted = Color(red: 0.12, green: 0.28, blue: 0.20)
    static let amber = Color(red: 1.0, green: 0.68, blue: 0.24)
    static let danger = Color(red: 1.0, green: 0.32, blue: 0.32)

    // Typography
    static let primaryText = Color.white
    static let secondaryText = Color.white.opacity(0.64)
    static let tertiaryText = Color.white.opacity(0.38)

    // Glass borders and hairlines
    static let hairline = Color.white.opacity(0.12)
    static let specularHighlight = Color.white.opacity(0.32)
}

struct MineralBackground: View {
    var body: some View {
        ZStack {
            ObsidianTheme.background
            RadialGradient(
                colors: [Color(red: 0.08, green: 0.22, blue: 0.16).opacity(0.4), .clear],
                center: UnitPoint(x: 0.5, y: 0.22),
                startRadius: 20,
                endRadius: 420
            )
            RadialGradient(
                colors: [Color(red: 0.05, green: 0.15, blue: 0.22).opacity(0.3), .clear],
                center: UnitPoint(x: 0.85, y: 0.75),
                startRadius: 40,
                endRadius: 480
            )
            LinearGradient(
                colors: [.black.opacity(0.5), .clear, .black.opacity(0.7)],
                startPoint: .top,
                endPoint: .bottom
            )
        }
        .ignoresSafeArea()
    }
}

struct AppleGlassModifier: ViewModifier {
    var cornerRadius: CGFloat = 24
    var highlightOpacity: Double = 0.22

    func body(content: Content) -> some View {
        content
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color.white.opacity(0.02))
            )
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(
                        LinearGradient(
                            colors: [
                                Color.white.opacity(highlightOpacity),
                                Color.white.opacity(0.04),
                                Color.white.opacity(0.01),
                                Color.white.opacity(0.08)
                            ],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            }
            .shadow(color: Color.black.opacity(0.35), radius: 18, x: 0, y: 10)
    }
}

extension View {
    func appleGlassCard(cornerRadius: CGFloat = 24, highlight: Double = 0.22) -> some View {
        modifier(AppleGlassModifier(cornerRadius: cornerRadius, highlightOpacity: highlight))
    }

    func obsidianCard() -> some View {
        appleGlassCard(cornerRadius: 24, highlight: 0.20)
    }
}
