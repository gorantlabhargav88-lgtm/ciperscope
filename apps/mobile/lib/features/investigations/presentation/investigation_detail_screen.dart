import 'package:flutter/material.dart';
import 'package:mobile/core/theme/theme.dart';

class InvestigationDetailScreen extends StatelessWidget {
  final String investigationId;

  const InvestigationDetailScreen({super.key, required this.investigationId});

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: Text('Investigation $investigationId'),
          bottom: const TabBar(
            tabs: [
              Tab(text: 'Overview'),
              Tab(text: 'Email Analysis'),
              Tab(text: 'Evidence'),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            _OverviewTab(),
            _EmailAnalysisTab(),
            _EvidenceTab(),
          ],
        ),
      ),
    );
  }
}

class _OverviewTab extends StatelessWidget {
  const _OverviewTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text('Overview Placeholder - Demo Data Only', style: TextStyle(color: AppTheme.textMuted)),
    );
  }
}

class _EmailAnalysisTab extends StatelessWidget {
  const _EmailAnalysisTab();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('Email Analysis Foundation', style: TextStyle(color: AppTheme.textMuted)),
          const SizedBox(height: 24),
          const Text('AI / NLP Analysis', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.all(16.0),
            decoration: BoxDecoration(
              color: AppTheme.primaryBlue,
              borderRadius: BorderRadius.circular(8.0),
              border: Border.all(color: const Color(0xFF1E293B)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: const [
                    Text('Status', style: TextStyle(color: AppTheme.textMuted)),
                    Text('MODEL NOT AVAILABLE', style: TextStyle(color: Colors.orange, fontWeight: FontWeight.bold)),
                  ],
                ),
                const SizedBox(height: 8),
                const Text('Message: No verified classification model is currently configured.', style: TextStyle(color: AppTheme.textMuted, fontStyle: FontStyle.italic)),
              ],
            ),
          )
        ],
      ),
    );
  }
}

class _EvidenceTab extends StatelessWidget {
  const _EvidenceTab();

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Text('Evidence Tracking Foundation - Awaiting Blockchain Integration', style: TextStyle(color: AppTheme.textMuted)),
    );
  }
}
