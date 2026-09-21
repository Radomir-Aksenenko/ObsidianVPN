import SwiftUI

enum ObsidianTheme {
    static let background = Color(red: 0.035, green: 0.038, blue: 0.036)
    static let surface = Color(red: 0.075, green: 0.08, blue: 0.076)
    static let raised = Color(red: 0.105, green: 0.11, blue: 0.106)
    static let accent = Color(red: 0.48, green: 0.82, blue: 0.56)
    static let accentMuted = Color(red: 0.18, green: 0.30, blue: 0.21)
    static let primaryText = Color(red: 0.95, green: 0.94, blue: 0.90)
    static let secondaryText = Color(red: 0.62, green: 0.62, blue: 0.59)
    static let hairline = Color.white.opacity(0.09)
    static let danger = Color(red: 0.95, green: 0.37, blue: 0.34)
}

struct MineralBackground: View {
    var body: some View {
        ZStack {
            ObsidianTheme.background
            RadialGradient(
                colors: [Color.white.opacity(0.055), .clear],
                center: UnitPoint(x: 0.48, y: 0.28),
                startRadius: 4,
                endRadius: 360
            )
            LinearGradient(
                colors: [.clear, ObsidianTheme.accent.opacity(0.025), .clear],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        }
        .ignoresSafeArea()
    }
}

struct ObsidianCardModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(ObsidianTheme.surface.opacity(0.92), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(ObsidianTheme.hairline, lineWidth: 1)
            }
    }
}

extension View {
    func obsidianCard() -> some View { modifier(ObsidianCardModifier()) }
}
