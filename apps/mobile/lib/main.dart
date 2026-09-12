import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/routing/router.dart';
import 'package:mobile/core/theme/theme.dart';

void main() {
  runApp(
    const ProviderScope(
      child: CiperScopeApp(),
    ),
  );
}

class CiperScopeApp extends ConsumerWidget {
  const CiperScopeApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(routerProvider);

    return MaterialApp.router(
      title: 'CiperScope',
      theme: AppTheme.darkTheme,
      routerConfig: router,
      debugShowCheckedModeBanner: false,
    );
  }
}
