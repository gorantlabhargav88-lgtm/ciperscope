import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:mobile/core/theme/theme.dart';
import 'package:mobile/features/auth/providers/auth_provider.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final _emailController = TextEditingController(text: 'admin@ciperscope.local');
  final _passwordController = TextEditingController(text: 'admin');

  @override
  Widget build(BuildContext context) {
    final authState = ref.watch(authNotifierProvider);

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(32.0),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Text(
                      'CiperScope',
                      style: TextStyle(
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                        color: AppTheme.textMain,
                        letterSpacing: 1.5,
                      ),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'SOC Command Center',
                      style: TextStyle(
                        color: AppTheme.textMuted,
                        fontSize: 16,
                      ),
                    ),
                    const SizedBox(height: 32),
                    TextField(
                      controller: _emailController,
                      decoration: const InputDecoration(
                        labelText: 'Email',
                        border: OutlineInputBorder(),
                      ),
                      keyboardType: TextInputType.emailAddress,
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _passwordController,
                      decoration: const InputDecoration(
                        labelText: 'Password',
                        border: OutlineInputBorder(),
                      ),
                      obscureText: true,
                    ),
                    const SizedBox(height: 24),
                    if (authState.error != null)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 16.0),
                        child: Text(
                          authState.error!,
                          style: const TextStyle(color: AppTheme.criticalRed),
                        ),
                      ),
                    SizedBox(
                      width: double.infinity,
                      height: 48,
                      child: ElevatedButton(
                        onPressed: authState.isLoading
                            ? null
                            : () {
                                ref.read(authNotifierProvider.notifier).login(
                                      _emailController.text,
                                      _passwordController.text,
                                    );
                              },
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppTheme.accentBlue,
                          foregroundColor: Colors.white,
                        ),
                        child: authState.isLoading
                            ? const CircularProgressIndicator(color: Colors.white)
                            : const Text('Login'),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }
}
