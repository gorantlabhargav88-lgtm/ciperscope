import 'package:flutter/material.dart';

class AppTheme {
  static const Color primaryBlue = Color(0xFF0F172A); // Navy
  static const Color accentBlue = Color(0xFF3B82F6);
  static const Color bgDark = Color(0xFF0B1120);
  static const Color textMain = Color(0xFFF1F5F9);
  static const Color textMuted = Color(0xFF94A3B8);

  static const Color criticalRed = Color(0xFFEF4444);
  static const Color highAmber = Color(0xFFF59E0B);
  static const Color mediumYellow = Color(0xFFFBBF24);
  static const Color lowGreen = Color(0xFF10B981);

  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: bgDark,
      primaryColor: primaryBlue,
      colorScheme: const ColorScheme.dark(
        primary: accentBlue,
        surface: primaryBlue,
        error: criticalRed,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: primaryBlue,
        elevation: 0,
        centerTitle: true,
      ),
      cardTheme: CardThemeData(
        color: primaryBlue,
        elevation: 2,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: const BorderSide(color: Color(0xFF1E293B)),
        ),
      ),
      textTheme: const TextTheme(
        bodyLarge: TextStyle(color: textMain, fontSize: 16),
        bodyMedium: TextStyle(color: textMain, fontSize: 14),
        bodySmall: TextStyle(color: textMuted, fontSize: 12),
        titleLarge: TextStyle(color: textMain, fontSize: 20, fontWeight: FontWeight.bold),
      ),
    );
  }
}
