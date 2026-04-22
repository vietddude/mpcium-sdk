import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'mpcium_sdk.dart';
import 'orchestration_client.dart';

void main() {
  runApp(const MpciumSampleApp());
}

const _defaultGrpcEndpoint = '10.0.2.2:50051';
const _defaultMqttBroker = 'tcp://10.0.2.2:1883';
const _defaultNodeId = 'flutter-sample-01';
const _defaultMqttUsername = _defaultNodeId;
const _defaultMqttPassword = _defaultNodeId;
const _defaultCoordinatorId = 'coordinator-01';
const _defaultCoordinatorPublicKeyHex =
    'b64ca8ec459081a299aecc2b2b5d555265b15ddfd29e792ddd08bedb418bdd0d';
const _defaultIdentityPrivateKeyHex =
    '666c75747465722d73616d706c652d30312d656432353531392d736565642121cad05e95eb9290a4255cf27cf22d269a3b0912e8b4055766e7b0dc5271b18a80';
const _defaultPeerParticipants =
    'peer-node-01,56a47a1103b610d6c85bf23ddb1f78ff6404f7c6f170d46441a268e105873cc4\n'
    'peer-node-02,d9034dd84e0dd10a57d6a09a8267b217051d5f121ff52fca66c2b485be16ae02';

class MpciumSampleApp extends StatelessWidget {
  const MpciumSampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    const fystackGreen = Color(0xff0f766e);
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Fystack MPC Mobile',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: fystackGreen,
          brightness: Brightness.light,
          surface: Colors.white,
        ),
        scaffoldBackgroundColor: const Color(0xfff6f8f7),
        useMaterial3: true,
        cardTheme: CardThemeData(
          color: Colors.white,
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
            side: const BorderSide(color: Color(0xffdbe5e2)),
          ),
        ),
        filledButtonTheme: FilledButtonThemeData(
          style: FilledButton.styleFrom(
            backgroundColor: fystackGreen,
            foregroundColor: Colors.white,
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          ),
        ),
        inputDecorationTheme: InputDecorationTheme(
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(8),
            borderSide: const BorderSide(color: Color(0xffdbe5e2)),
          ),
          filled: true,
          fillColor: Colors.white,
        ),
      ),
      home: const RuntimePage(),
    );
  }
}

class RuntimePage extends StatefulWidget {
  const RuntimePage({super.key});

  @override
  State<RuntimePage> createState() => _RuntimePageState();
}

class _RuntimePageState extends State<RuntimePage> {
  final _grpcEndpoint = TextEditingController(text: _defaultGrpcEndpoint);
  final _mqttBroker = TextEditingController(text: _defaultMqttBroker);
  final _mqttUsername = TextEditingController(text: _defaultMqttUsername);
  final _mqttPassword = TextEditingController(text: _defaultMqttPassword);
  final _nodeId = TextEditingController(text: _defaultNodeId);
  final _coordinatorId = TextEditingController(text: _defaultCoordinatorId);
  final _coordinatorPublicKey = TextEditingController(
    text: _defaultCoordinatorPublicKeyHex,
  );
  final _participants = TextEditingController(text: _defaultPeerParticipants);
  final _keygenWalletId = TextEditingController();
  final _signWalletId = TextEditingController();
  final _signingInput = TextEditingController(text: '68656c6c6f206d7063');
  final _derivationPath = TextEditingController();
  final _derivationDelta = TextEditingController();
  final _logScrollController = ScrollController();

  final List<String> _logs = <String>[];
  final List<String> _walletIds = <String>[];
  StreamSubscription<List<MpciumEvent>>? _eventSubscription;
  MpciumIdentity? _identity;
  SessionResultView? _keygenResult;
  SessionResultView? _signResult;
  String _keygenProtocol = '';
  String _signProtocol = 'ECDSA';
  int _threshold = 1;
  bool _initializing = false;
  bool _runtimeStarted = false;
  bool _keygenPending = false;
  bool _signPending = false;
  String? _pendingSignSessionId;
  String? _approvalDialogSessionId;

  bool get _runtimeReady => _identity != null && _runtimeStarted;

  @override
  void initState() {
    super.initState();
    _eventSubscription = MpciumSdk.events.listen(
      _handleEvents,
      onError: (Object error) => _appendLog('Event stream failed: $error'),
    );
  }

  @override
  void dispose() {
    _eventSubscription?.cancel();
    _grpcEndpoint.dispose();
    _mqttBroker.dispose();
    _mqttUsername.dispose();
    _mqttPassword.dispose();
    _nodeId.dispose();
    _coordinatorId.dispose();
    _coordinatorPublicKey.dispose();
    _participants.dispose();
    _keygenWalletId.dispose();
    _signWalletId.dispose();
    _signingInput.dispose();
    _derivationPath.dispose();
    _derivationDelta.dispose();
    _logScrollController.dispose();
    unawaited(MpciumSdk.stop());
    super.dispose();
  }

  Future<void> _connect() async {
    if (_initializing) return;
    setState(() {
      _initializing = true;
    });
    try {
      final identity =
          await MpciumSdk.initialize(configJson: _runtimeConfigJson());
      await MpciumSdk.start();
      if (!mounted) return;
      setState(() {
        _identity = identity;
        _runtimeStarted = true;
        _initializing = false;
      });
      _appendLog('Mobile runtime online as ${identity.participantId}');
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _initializing = false;
        _runtimeStarted = false;
      });
      _appendLog('Connect failed: $error');
    }
  }

  Future<void> _requestKeygen() async {
    if (!_runtimeReady || _keygenPending) return;
    final walletId = _ensureKeygenWalletId();
    setState(() {
      _keygenPending = true;
      _keygenResult = null;
    });
    try {
      final result =
          await OrchestrationClient(endpoint: _grpcEndpoint.text).keygen(
        KeygenInput(
          threshold: _threshold,
          walletId: walletId,
          participants: _allParticipants(),
          protocol: _keygenProtocol,
        ),
      );
      if (!mounted) return;
      setState(() {
        _keygenResult = result;
        if (result.hasKey) {
          _rememberWallet(walletId);
        }
        _keygenPending = false;
      });
      _appendLog(
        'Keygen ${result.statusLabel.toLowerCase()} session=${result.sessionId} '
        'key=${result.keyId} ecdsa=${_previewHex(result.ecdsaPubkey)} '
        'eddsa=${_previewHex(result.eddsaPubkey)}',
      );
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _keygenResult = SessionResultView.failure(error);
        _keygenPending = false;
      });
      _appendLog('Keygen failed: $error');
    }
  }

  Future<void> _requestSign() async {
    if (!_runtimeReady || _signPending || _signWalletId.text.trim().isEmpty) {
      return;
    }
    setState(() {
      _signPending = true;
      _signResult = null;
    });
    try {
      final result =
          await OrchestrationClient(endpoint: _grpcEndpoint.text).sign(
        SignInput(
          protocol: _signProtocol,
          threshold: _threshold,
          walletId: _signWalletId.text.trim(),
          signingInputHex: _cleanHex(_signingInput.text),
          participants: _allParticipants(),
          derivationPath: _parsePath(_derivationPath.text),
          derivationDeltaHex: _cleanHex(_derivationDelta.text),
        ),
      );
      if (!mounted) return;
      setState(() {
        _signResult = result;
        _signPending = false;
      });
      _appendLog('Sign result session=${result.sessionId}');
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _signResult = SessionResultView.failure(error);
        _signPending = false;
      });
      _appendLog('Sign failed: $error');
    }
  }

  Future<void> _copy(String label, String value) async {
    if (value.isEmpty) return;
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied')),
    );
  }

  String _ensureKeygenWalletId() {
    final existing = _keygenWalletId.text.trim();
    if (existing.isNotEmpty) return existing;
    final generated = _generateWalletId();
    _keygenWalletId.text = generated;
    return generated;
  }

  String _generateWalletId() {
    final now = DateTime.now().millisecondsSinceEpoch;
    return 'wallet_$now';
  }

  void _rememberWallet(String walletId) {
    if (walletId.isEmpty || _walletIds.contains(walletId)) return;
    _walletIds.add(walletId);
    _signWalletId.text = walletId;
  }

  String _previewHex(String value) {
    if (value.isEmpty) return '<empty>';
    if (value.length <= 18) return value;
    return '${value.substring(0, 10)}...${value.substring(value.length - 8)}';
  }

  List<ParticipantInput> _allParticipants() {
    final parsed = <ParticipantInput>[];
    for (final rawLine in _participants.text.split('\n')) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;
      final parts = line.split(',');
      if (parts.length != 2) {
        throw FormatException('Invalid participant line: "$line"');
      }
      parsed.add(ParticipantInput(
        id: parts[0].trim(),
        identityPublicKeyHex: _cleanHex(parts[1]),
      ));
    }
    final identity = _identity;
    if (identity == null) {
      throw StateError('mobile identity is not ready');
    }
    parsed.removeWhere((p) => p.id == identity.participantId);
    parsed.add(ParticipantInput(
      id: identity.participantId,
      identityPublicKeyHex: identity.identityPublicKeyHex,
    ));
    return parsed;
  }

  List<int> _parsePath(String value) {
    final clean = value.trim();
    if (clean.isEmpty) return const <int>[];
    return clean
        .split('/')
        .map((part) => part.trim())
        .where((part) => part.isNotEmpty && part != 'm')
        .map((part) => int.parse(part))
        .toList(growable: false);
  }

  String _runtimeConfigJson() {
    return jsonEncode(<String, Object?>{
      'node_id': _nodeId.text.trim(),
      'coordinator_id': _coordinatorId.text.trim(),
      'coordinator_public_key_base64': _hexToBase64(_coordinatorPublicKey.text),
      // Keep sample participant identity stable across fresh installs.
      'identity_private_key_base64':
          _hexToBase64(_defaultIdentityPrivateKeyHex),
      'transport': <String, Object?>{'mode': 'native'},
      'store': <String, Object?>{'mode': 'native'},
      'mqtt': <String, Object?>{
        'broker': _mqttBroker.text.trim(),
        'client_id': _nodeId.text.trim(),
        'username': _mqttUsername.text.trim(),
        'password': _mqttPassword.text,
      },
      'presence_interval_ms': 5000,
      'tick_interval_ms': 250,
    });
  }

  String _hexToBase64(String value) {
    final clean = _cleanHex(value);
    final bytes = <int>[];
    for (var i = 0; i < clean.length; i += 2) {
      bytes.add(int.parse(clean.substring(i, i + 2), radix: 16));
    }
    return base64Encode(bytes);
  }

  String _cleanHex(String value) {
    return value.trim().replaceFirst(RegExp(r'^0x'), '').replaceAll(' ', '');
  }

  void _handleEvents(List<MpciumEvent> events) {
    if (!mounted) return;
    for (final event in events) {
      if (event.type == 'native_log') {
        _appendLog(event.message);
        continue;
      }
      _appendLog(jsonEncode(event.data));
      final sessionId = event.sessionId;
      if (event.type == 'sign_approval_required' && sessionId.isNotEmpty) {
        setState(() {
          _pendingSignSessionId = sessionId;
        });
        _showSignApprovalDialog(sessionId);
      }
      if ((event.type == 'session_completed' ||
              event.type == 'session_failed') &&
          sessionId.isNotEmpty &&
          sessionId == _pendingSignSessionId) {
        setState(() {
          _pendingSignSessionId = null;
          if (_approvalDialogSessionId == sessionId) {
            _approvalDialogSessionId = null;
          }
        });
      }
    }
  }

  void _showSignApprovalDialog(String sessionId) {
    if (_approvalDialogSessionId == sessionId) return;
    _approvalDialogSessionId = sessionId;
    showDialog<void>(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('Approve SIGN'),
          content: SelectableText('Session: $sessionId'),
          actions: <Widget>[
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Not now'),
            ),
            FilledButton.icon(
              onPressed: () {
                Navigator.of(context).pop();
                unawaited(_approveSign(sessionId));
              },
              icon: const Icon(Icons.check),
              label: const Text('Approve'),
            ),
          ],
        );
      },
    ).whenComplete(() {
      if (!mounted) return;
      if (_approvalDialogSessionId == sessionId) {
        setState(() {
          _approvalDialogSessionId = null;
        });
      }
    });
  }

  Future<void> _approveSign(String sessionId) async {
    try {
      await MpciumSdk.approveSign(sessionId, approved: true);
      if (!mounted) return;
      setState(() {
        _pendingSignSessionId = null;
      });
      _appendLog('Approved SIGN session=$sessionId');
    } catch (error) {
      _appendLog('Approve SIGN failed: $error');
    }
  }

  void _appendLog(String line) {
    if (!mounted) return;
    setState(() {
      _logs.add(line);
      if (_logs.length > 300) {
        _logs.removeRange(0, _logs.length - 300);
      }
    });
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_logScrollController.hasClients) return;
      _logScrollController.animateTo(
        _logScrollController.position.maxScrollExtent,
        duration: const Duration(milliseconds: 160),
        curve: Curves.easeOut,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('Fystack MPC Mobile'),
          bottom: const TabBar(
            tabs: <Widget>[
              Tab(icon: Icon(Icons.hub_outlined), text: 'Connect'),
              Tab(icon: Icon(Icons.key_outlined), text: 'Keygen'),
              Tab(icon: Icon(Icons.draw_outlined), text: 'Sign'),
            ],
          ),
        ),
        body: SafeArea(
          child: TabBarView(
            children: <Widget>[
              _ConnectScreen(
                grpcEndpoint: _grpcEndpoint,
                mqttBroker: _mqttBroker,
                mqttUsername: _mqttUsername,
                mqttPassword: _mqttPassword,
                nodeId: _nodeId,
                coordinatorId: _coordinatorId,
                coordinatorPublicKey: _coordinatorPublicKey,
                identity: _identity,
                runtimeStarted: _runtimeStarted,
                initializing: _initializing,
                onConnect: _connect,
                onCopy: _copy,
                logs: _logs,
                logScrollController: _logScrollController,
              ),
              _KeygenScreen(
                enabled: _runtimeReady,
                identity: _identity,
                protocol: _keygenProtocol,
                threshold: _threshold,
                walletId: _keygenWalletId,
                participants: _participants,
                result: _keygenResult,
                pending: _keygenPending,
                onProtocolChanged: (value) =>
                    setState(() => _keygenProtocol = value),
                onThresholdChanged: (value) =>
                    setState(() => _threshold = value),
                onSubmit: _requestKeygen,
                onCopy: _copy,
              ),
              _SignScreen(
                enabled: _runtimeReady,
                protocol: _signProtocol,
                walletId: _signWalletId,
                walletIds: _walletIds,
                signingInput: _signingInput,
                derivationPath: _derivationPath,
                derivationDelta: _derivationDelta,
                result: _signResult,
                pending: _signPending,
                pendingApprovalSession: _pendingSignSessionId,
                onProtocolChanged: (value) =>
                    setState(() => _signProtocol = value),
                onWalletChanged: (value) =>
                    setState(() => _signWalletId.text = value),
                onSubmit: _requestSign,
                onCopy: _copy,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ConnectScreen extends StatelessWidget {
  const _ConnectScreen({
    required this.grpcEndpoint,
    required this.mqttBroker,
    required this.mqttUsername,
    required this.mqttPassword,
    required this.nodeId,
    required this.coordinatorId,
    required this.coordinatorPublicKey,
    required this.identity,
    required this.runtimeStarted,
    required this.initializing,
    required this.onConnect,
    required this.onCopy,
    required this.logs,
    required this.logScrollController,
  });

  final TextEditingController grpcEndpoint;
  final TextEditingController mqttBroker;
  final TextEditingController mqttUsername;
  final TextEditingController mqttPassword;
  final TextEditingController nodeId;
  final TextEditingController coordinatorId;
  final TextEditingController coordinatorPublicKey;
  final MpciumIdentity? identity;
  final bool runtimeStarted;
  final bool initializing;
  final VoidCallback onConnect;
  final Future<void> Function(String label, String value) onCopy;
  final List<String> logs;
  final ScrollController logScrollController;

  @override
  Widget build(BuildContext context) {
    final fieldsEnabled = !runtimeStarted && !initializing;
    return _Page(
      children: <Widget>[
        _SectionCard(
          title: 'Server connection',
          child: Column(
            children: <Widget>[
              _Field(
                controller: grpcEndpoint,
                label: 'Coordinator gRPC endpoint',
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: mqttBroker,
                label: 'MQTT relay broker',
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: mqttUsername,
                label: 'MQTT username',
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: mqttPassword,
                label: 'MQTT password',
                obscureText: true,
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: nodeId,
                label: 'Mobile participant ID',
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: coordinatorId,
                label: 'Coordinator ID',
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: coordinatorPublicKey,
                label: 'Coordinator public key hex',
                minLines: 2,
                enabled: fieldsEnabled,
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: initializing ? null : onConnect,
                  icon: initializing
                      ? const SizedBox.square(
                          dimension: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.power_settings_new),
                  label: Text(
                      runtimeStarted ? 'Reconnect runtime' : 'Connect runtime'),
                ),
              ),
            ],
          ),
        ),
        _SectionCard(
          title: 'Mobile wallet identity',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              _StatusPill(
                label: runtimeStarted ? 'Runtime online' : 'Runtime offline',
                active: runtimeStarted,
              ),
              const SizedBox(height: 12),
              _CopyLine(
                label: 'Participant',
                value: identity?.participantId ?? 'not connected',
                onCopy: onCopy,
              ),
              const SizedBox(height: 10),
              _CopyLine(
                label: 'Identity public key',
                value: identity?.identityPublicKeyHex ?? 'not connected',
                onCopy: onCopy,
              ),
            ],
          ),
        ),
        _LogPanel(controller: logScrollController, logs: logs),
      ],
    );
  }
}

class _KeygenScreen extends StatelessWidget {
  const _KeygenScreen({
    required this.enabled,
    required this.identity,
    required this.protocol,
    required this.threshold,
    required this.walletId,
    required this.participants,
    required this.result,
    required this.pending,
    required this.onProtocolChanged,
    required this.onThresholdChanged,
    required this.onSubmit,
    required this.onCopy,
  });

  final bool enabled;
  final MpciumIdentity? identity;
  final String protocol;
  final int threshold;
  final TextEditingController walletId;
  final TextEditingController participants;
  final SessionResultView? result;
  final bool pending;
  final ValueChanged<String> onProtocolChanged;
  final ValueChanged<int> onThresholdChanged;
  final VoidCallback onSubmit;
  final Future<void> Function(String label, String value) onCopy;

  @override
  Widget build(BuildContext context) {
    return _Page(
      children: <Widget>[
        _SessionConfigCard(
          enabled: enabled,
          identity: identity,
          protocol: protocol,
          threshold: threshold,
          walletId: walletId,
          participants: participants,
          onProtocolChanged: onProtocolChanged,
          onThresholdChanged: onThresholdChanged,
        ),
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            onPressed: enabled && !pending ? onSubmit : null,
            icon: pending
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.key),
            label: Text(pending ? 'Waiting for keygen result' : 'Create key'),
          ),
        ),
        _ResultCard(result: result, mode: _ResultMode.keygen, onCopy: onCopy),
      ],
    );
  }
}

class _SignScreen extends StatelessWidget {
  const _SignScreen({
    required this.enabled,
    required this.protocol,
    required this.walletId,
    required this.walletIds,
    required this.signingInput,
    required this.derivationPath,
    required this.derivationDelta,
    required this.result,
    required this.pending,
    required this.pendingApprovalSession,
    required this.onProtocolChanged,
    required this.onWalletChanged,
    required this.onSubmit,
    required this.onCopy,
  });

  final bool enabled;
  final String protocol;
  final TextEditingController walletId;
  final List<String> walletIds;
  final TextEditingController signingInput;
  final TextEditingController derivationPath;
  final TextEditingController derivationDelta;
  final SessionResultView? result;
  final bool pending;
  final String? pendingApprovalSession;
  final ValueChanged<String> onProtocolChanged;
  final ValueChanged<String> onWalletChanged;
  final VoidCallback onSubmit;
  final Future<void> Function(String label, String value) onCopy;

  @override
  Widget build(BuildContext context) {
    return _Page(
      children: <Widget>[
        _SignConfigCard(
          enabled: enabled,
          protocol: protocol,
          walletId: walletId,
          walletIds: walletIds,
          onProtocolChanged: onProtocolChanged,
          onWalletChanged: onWalletChanged,
        ),
        _SectionCard(
          title: 'Signing input',
          child: Column(
            children: <Widget>[
              _Field(
                controller: signingInput,
                label: 'Hex message',
                minLines: 3,
              ),
              const SizedBox(height: 10),
              _Field(
                controller: derivationPath,
                label: 'Derivation path, optional',
                hint: 'm/44/60/0/0/0',
              ),
              const SizedBox(height: 10),
              _Field(
                controller: derivationDelta,
                label: 'Derivation delta hex, optional',
              ),
              if (pendingApprovalSession != null) ...<Widget>[
                const SizedBox(height: 12),
                _StatusPill(
                  label: 'Approval pending: $pendingApprovalSession',
                  active: false,
                ),
              ],
            ],
          ),
        ),
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            onPressed:
                enabled && !pending && walletIds.isNotEmpty ? onSubmit : null,
            icon: pending
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.draw),
            label: Text(pending ? 'Waiting for signature' : 'Sign message'),
          ),
        ),
        _ResultCard(result: result, mode: _ResultMode.sign, onCopy: onCopy),
      ],
    );
  }
}

class _SessionConfigCard extends StatelessWidget {
  const _SessionConfigCard({
    required this.enabled,
    required this.identity,
    required this.protocol,
    required this.threshold,
    required this.walletId,
    required this.participants,
    required this.onProtocolChanged,
    required this.onThresholdChanged,
  });

  final bool enabled;
  final MpciumIdentity? identity;
  final String protocol;
  final int threshold;
  final TextEditingController walletId;
  final TextEditingController participants;
  final ValueChanged<String> onProtocolChanged;
  final ValueChanged<int> onThresholdChanged;

  @override
  Widget build(BuildContext context) {
    return _SectionCard(
      title: 'Session config',
      child: Column(
        children: <Widget>[
          SegmentedButton<String>(
            segments: const <ButtonSegment<String>>[
              ButtonSegment(value: 'ECDSA', label: Text('ECDSA')),
              ButtonSegment(value: 'EdDSA', label: Text('EdDSA')),
              ButtonSegment(value: '', label: Text('Both')),
            ],
            selected: <String>{protocol},
            onSelectionChanged:
                enabled ? (values) => onProtocolChanged(values.first) : null,
          ),
          const SizedBox(height: 12),
          _Field(
            controller: walletId,
            label: 'Wallet ID',
            hint: 'Leave blank to auto-generate from timestamp',
          ),
          const SizedBox(height: 12),
          Row(
            children: <Widget>[
              Expanded(
                child: Text(
                  'Threshold',
                  style: Theme.of(context).textTheme.labelLarge,
                ),
              ),
              IconButton.filledTonal(
                onPressed: enabled && threshold > 1
                    ? () => onThresholdChanged(threshold - 1)
                    : null,
                icon: const Icon(Icons.remove),
              ),
              SizedBox(
                width: 48,
                child: Center(
                  child: Text(
                    '$threshold',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
              ),
              IconButton.filledTonal(
                onPressed:
                    enabled ? () => onThresholdChanged(threshold + 1) : null,
                icon: const Icon(Icons.add),
              ),
            ],
          ),
          const SizedBox(height: 12),
          _PeerParticipantsEditor(
            controller: participants,
            enabled: enabled,
            identity: identity,
          ),
        ],
      ),
    );
  }
}

class _SignConfigCard extends StatelessWidget {
  const _SignConfigCard({
    required this.enabled,
    required this.protocol,
    required this.walletId,
    required this.walletIds,
    required this.onProtocolChanged,
    required this.onWalletChanged,
  });

  final bool enabled;
  final String protocol;
  final TextEditingController walletId;
  final List<String> walletIds;
  final ValueChanged<String> onProtocolChanged;
  final ValueChanged<String> onWalletChanged;

  @override
  Widget build(BuildContext context) {
    final selectedProtocol = protocol.isEmpty ? 'ECDSA' : protocol;
    final selectedWallet =
        walletIds.contains(walletId.text) ? walletId.text : null;
    return _SectionCard(
      title: 'Session config',
      child: Column(
        children: <Widget>[
          SegmentedButton<String>(
            segments: const <ButtonSegment<String>>[
              ButtonSegment(value: 'ECDSA', label: Text('ECDSA')),
              ButtonSegment(value: 'EdDSA', label: Text('EdDSA')),
            ],
            selected: <String>{selectedProtocol},
            onSelectionChanged:
                enabled ? (values) => onProtocolChanged(values.first) : null,
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            initialValue: selectedWallet,
            items: walletIds
                .map(
                  (walletId) => DropdownMenuItem<String>(
                    value: walletId,
                    child: Text(walletId),
                  ),
                )
                .toList(growable: false),
            onChanged: enabled && walletIds.isNotEmpty
                ? (value) {
                    if (value != null) onWalletChanged(value);
                  }
                : null,
            decoration: const InputDecoration(
              labelText: 'Wallet',
              hintText: 'Run keygen first',
            ),
          ),
        ],
      ),
    );
  }
}

class _PeerParticipantsEditor extends StatefulWidget {
  const _PeerParticipantsEditor({
    required this.controller,
    required this.enabled,
    required this.identity,
  });

  final TextEditingController controller;
  final bool enabled;
  final MpciumIdentity? identity;

  @override
  State<_PeerParticipantsEditor> createState() =>
      _PeerParticipantsEditorState();
}

class _PeerParticipantsEditorState extends State<_PeerParticipantsEditor> {
  final List<_PeerParticipantFields> _peers = <_PeerParticipantFields>[];
  bool _syncing = false;

  @override
  void initState() {
    super.initState();
    _loadFromController();
  }

  @override
  void didUpdateWidget(covariant _PeerParticipantsEditor oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      _disposePeers();
      _loadFromController();
    }
  }

  @override
  void dispose() {
    _disposePeers();
    super.dispose();
  }

  void _loadFromController() {
    final rows = widget.controller.text
        .split('\n')
        .map((line) => line.trim())
        .where((line) => line.isNotEmpty);
    for (final row in rows) {
      final parts = row.split(',');
      _addPeer(
        id: parts.isNotEmpty ? parts[0].trim() : '',
        publicKey: parts.length > 1 ? parts[1].trim() : '',
        sync: false,
      );
    }
    if (_peers.isEmpty) {
      _addPeer(sync: false);
    }
    _syncController();
  }

  void _disposePeers() {
    for (final peer in _peers) {
      peer.dispose();
    }
    _peers.clear();
  }

  void _addPeer({String? id, String publicKey = '', bool sync = true}) {
    final peer = _PeerParticipantFields(
      id: id ?? 'peer-node-${(_peers.length + 1).toString().padLeft(2, '0')}',
      publicKey: publicKey,
      onChanged: _syncController,
    );
    setState(() {
      _peers.add(peer);
    });
    if (sync) _syncController();
  }

  void _removePeer(int index) {
    if (_peers.length == 1) return;
    final peer = _peers.removeAt(index);
    peer.dispose();
    setState(() {});
    _syncController();
  }

  void _setPeerEnabled(int index, bool value) {
    setState(() {
      _peers[index].enabled = value;
    });
    _syncController();
  }

  Future<void> _editPeer(int index) async {
    final peer = _peers[index];
    final id = TextEditingController(text: peer.id.text);
    final publicKey = TextEditingController(text: peer.publicKey.text);
    final action = await showDialog<_PeerEditAction>(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: Text('Peer node ${index + 1}'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                _Field(controller: id, label: 'Node ID'),
                const SizedBox(height: 10),
                _Field(
                  controller: publicKey,
                  label: 'Identity public key hex',
                  minLines: 2,
                ),
              ],
            ),
          ),
          actions: <Widget>[
            if (_peers.length > 1)
              TextButton.icon(
                onPressed: () =>
                    Navigator.of(context).pop(_PeerEditAction.remove),
                icon: const Icon(Icons.delete_outline),
                label: const Text('Remove'),
              ),
            TextButton(
              onPressed: () =>
                  Navigator.of(context).pop(_PeerEditAction.cancel),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () => Navigator.of(context).pop(_PeerEditAction.save),
              child: const Text('Save'),
            ),
          ],
        );
      },
    );

    if (!mounted) return;
    switch (action) {
      case _PeerEditAction.save:
        setState(() {
          peer.id.text = id.text;
          peer.publicKey.text = publicKey.text;
        });
        _syncController();
        break;
      case _PeerEditAction.remove:
        _removePeer(index);
        break;
      case _PeerEditAction.cancel:
      case null:
        break;
    }
    id.dispose();
    publicKey.dispose();
  }

  void _syncController() {
    if (_syncing) return;
    _syncing = true;
    widget.controller.text = _peers
        .map((peer) {
          if (!peer.enabled) return '';
          final id = peer.id.text.trim();
          final publicKey = peer.publicKey.text.trim();
          if (id.isEmpty && publicKey.isEmpty) return '';
          return '$id,$publicKey';
        })
        .where((line) => line.isNotEmpty)
        .join('\n');
    _syncing = false;
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        Row(
          children: <Widget>[
            Expanded(
              child: Text(
                'Peer nodes',
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
            IconButton.filledTonal(
              onPressed: widget.enabled ? () => _addPeer() : null,
              icon: const Icon(Icons.add),
              tooltip: 'Add peer node',
            ),
          ],
        ),
        const SizedBox(height: 8),
        _SelfParticipantRow(identity: widget.identity),
        const SizedBox(height: 8),
        for (var i = 0; i < _peers.length; i++) ...<Widget>[
          _PeerParticipantRow(
            index: i,
            fields: _peers[i],
            enabled: widget.enabled,
            onEnabledChanged: (value) => _setPeerEnabled(i, value),
            onTap: () => _editPeer(i),
          ),
          if (i != _peers.length - 1) const SizedBox(height: 8),
        ],
      ],
    );
  }
}

class _PeerParticipantFields {
  _PeerParticipantFields({
    required String id,
    required String publicKey,
    required VoidCallback onChanged,
  })  : id = TextEditingController(text: id),
        publicKey = TextEditingController(text: publicKey) {
    this.id.addListener(onChanged);
    this.publicKey.addListener(onChanged);
  }

  final TextEditingController id;
  final TextEditingController publicKey;
  bool enabled = true;

  void dispose() {
    id.dispose();
    publicKey.dispose();
  }
}

class _SelfParticipantRow extends StatelessWidget {
  const _SelfParticipantRow({required this.identity});

  final MpciumIdentity? identity;

  @override
  Widget build(BuildContext context) {
    final nodeId = identity?.participantId ?? 'Self device';
    final publicKey = identity?.identityPublicKeyHex ?? '';
    final publicKeyPreview = publicKey.length <= 16
        ? publicKey
        : '${publicKey.substring(0, 10)}...${publicKey.substring(publicKey.length - 6)}';
    return Material(
      color: const Color(0xffeef7f5),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
        side: BorderSide(color: Theme.of(context).colorScheme.primary),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        child: Row(
          children: <Widget>[
            Icon(
              Icons.phone_android,
              color: Theme.of(context).colorScheme.primary,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Row(
                    children: <Widget>[
                      Flexible(
                        child: Text(
                          nodeId,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: Theme.of(context).textTheme.labelLarge,
                        ),
                      ),
                      const SizedBox(width: 8),
                      const _StatusPill(label: 'Self', active: true),
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    publicKeyPreview.isEmpty
                        ? 'Connect runtime first'
                        : publicKeyPreview,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          fontFamily: 'monospace',
                          color: const Color(0xff5f6f6b),
                        ),
                  ),
                ],
              ),
            ),
            const Switch(value: true, onChanged: null),
          ],
        ),
      ),
    );
  }
}

class _PeerParticipantRow extends StatelessWidget {
  const _PeerParticipantRow({
    required this.index,
    required this.fields,
    required this.enabled,
    required this.onEnabledChanged,
    required this.onTap,
  });

  final int index;
  final _PeerParticipantFields fields;
  final bool enabled;
  final ValueChanged<bool> onEnabledChanged;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final nodeId = fields.id.text.trim();
    final publicKey = fields.publicKey.text.trim();
    final publicKeyPreview = publicKey.length <= 16
        ? publicKey
        : '${publicKey.substring(0, 10)}...${publicKey.substring(publicKey.length - 6)}';
    return Material(
      color: const Color(0xfffbfcfb),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(8),
        side: const BorderSide(color: Color(0xffdbe5e2)),
      ),
      child: InkWell(
        onTap: enabled ? onTap : null,
        borderRadius: BorderRadius.circular(8),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          child: Row(
            children: <Widget>[
              Icon(
                Icons.account_tree_outlined,
                color: fields.enabled
                    ? Theme.of(context).colorScheme.primary
                    : Theme.of(context).disabledColor,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Text(
                      nodeId.isEmpty ? 'Peer node ${index + 1}' : nodeId,
                      style: Theme.of(context).textTheme.labelLarge,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      publicKeyPreview.isEmpty
                          ? 'No public key'
                          : publicKeyPreview,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            fontFamily: 'monospace',
                            color: const Color(0xff5f6f6b),
                          ),
                    ),
                  ],
                ),
              ),
              Switch(
                value: fields.enabled,
                onChanged: enabled ? onEnabledChanged : null,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

enum _PeerEditAction { save, remove, cancel }

enum _ResultMode { keygen, sign }

class _ResultCard extends StatelessWidget {
  const _ResultCard({
    required this.result,
    required this.mode,
    required this.onCopy,
  });

  final SessionResultView? result;
  final _ResultMode mode;
  final Future<void> Function(String label, String value) onCopy;

  @override
  Widget build(BuildContext context) {
    final result = this.result;
    final status = result?.statusLabel ?? '';
    return _SectionCard(
      title: mode == _ResultMode.keygen ? 'Key result' : 'Signature result',
      child: result == null
          ? Text(
              'No result yet',
              style: Theme.of(context).textTheme.bodyMedium,
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                _StatusPill(
                  label: status,
                  active: result.accepted && result.error.isEmpty,
                ),
                const SizedBox(height: 12),
                _CopyLine(
                    label: 'Session ID',
                    value: result.sessionId,
                    onCopy: onCopy),
                if (result.expiresAt.isNotEmpty)
                  _CopyLine(
                      label: 'Expires at',
                      value: result.expiresAt,
                      onCopy: onCopy),
                if (result.keyId.isNotEmpty)
                  _CopyLine(
                      label: 'Key ID', value: result.keyId, onCopy: onCopy),
                if (result.publicKeyHex.isNotEmpty)
                  _CopyLine(
                      label: 'Public key',
                      value: result.publicKeyHex,
                      onCopy: onCopy),
                if (result.ecdsaPubkey.isNotEmpty)
                  _CopyLine(
                      label: 'ECDSA public key',
                      value: result.ecdsaPubkey,
                      onCopy: onCopy),
                if (result.eddsaPubkey.isNotEmpty)
                  _CopyLine(
                      label: 'EdDSA public key',
                      value: result.eddsaPubkey,
                      onCopy: onCopy),
                if (result.signatureHex.isNotEmpty)
                  _CopyLine(
                      label: 'Signature',
                      value: result.signatureHex,
                      onCopy: onCopy),
                if (result.rHex.isNotEmpty)
                  _CopyLine(label: 'R', value: result.rHex, onCopy: onCopy),
                if (result.sHex.isNotEmpty)
                  _CopyLine(label: 'S', value: result.sHex, onCopy: onCopy),
                if (result.signatureRecoveryHex.isNotEmpty)
                  _CopyLine(
                    label: 'Recovery',
                    value: result.signatureRecoveryHex,
                    onCopy: onCopy,
                  ),
                if (result.error.isNotEmpty)
                  _CopyLine(
                      label: 'Error', value: result.error, onCopy: onCopy),
                if (result.accepted &&
                    !result.completed &&
                    result.error.isEmpty)
                  Text(
                    'Session accepted, waiting result returned no key or error.',
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
              ],
            ),
    );
  }
}

extension _SessionResultViewStatus on SessionResultView {
  String get statusLabel {
    if (!accepted) return 'Rejected';
    if (error.isNotEmpty) return 'Failed';
    if (completed) return 'Completed';
    return 'Accepted';
  }
}

class _Page extends StatelessWidget {
  const _Page({required this.children});

  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return ListView.separated(
      padding: const EdgeInsets.all(16),
      itemBuilder: (context, index) => children[index],
      separatorBuilder: (_, __) => const SizedBox(height: 12),
      itemCount: children.length,
    );
  }
}

class _SectionCard extends StatelessWidget {
  const _SectionCard({
    required this.title,
    required this.child,
  });

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field({
    required this.controller,
    required this.label,
    this.hint,
    this.minLines = 1,
    this.obscureText = false,
    this.enabled = true,
  });

  final TextEditingController controller;
  final String label;
  final String? hint;
  final int minLines;
  final bool obscureText;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: controller,
      enabled: enabled,
      minLines: minLines,
      maxLines: minLines == 1 ? 1 : 6,
      obscureText: obscureText,
      autocorrect: false,
      enableSuggestions: false,
      style: const TextStyle(fontFamily: 'monospace'),
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
      ),
    );
  }
}

class _CopyLine extends StatelessWidget {
  const _CopyLine({
    required this.label,
    required this.value,
    required this.onCopy,
  });

  final String label;
  final String value;
  final Future<void> Function(String label, String value) onCopy;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(label, style: Theme.of(context).textTheme.labelMedium),
                const SizedBox(height: 2),
                SelectableText(
                  value.isEmpty ? '-' : value,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        fontFamily: 'monospace',
                        height: 1.25,
                      ),
                ),
              ],
            ),
          ),
          IconButton(
            tooltip: 'Copy $label',
            onPressed: value.isEmpty || value == 'not connected'
                ? null
                : () => unawaited(onCopy(label, value)),
            icon: const Icon(Icons.copy, size: 18),
          ),
        ],
      ),
    );
  }
}

class _StatusPill extends StatelessWidget {
  const _StatusPill({
    required this.label,
    required this.active,
  });

  final String label;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final color = active ? const Color(0xff0f766e) : const Color(0xff9a6b00);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        child: Text(
          label,
          style: TextStyle(color: color, fontWeight: FontWeight.w600),
        ),
      ),
    );
  }
}

class _LogPanel extends StatelessWidget {
  const _LogPanel({
    required this.controller,
    required this.logs,
  });

  final ScrollController controller;
  final List<String> logs;

  @override
  Widget build(BuildContext context) {
    return _SectionCard(
      title: 'Runtime logs',
      child: SizedBox(
        height: 180,
        child: logs.isEmpty
            ? const Text('No logs yet')
            : ListView.builder(
                controller: controller,
                itemCount: logs.length,
                itemBuilder: (BuildContext context, int index) {
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: SelectableText(
                      logs[index],
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            fontFamily: 'monospace',
                            height: 1.3,
                          ),
                    ),
                  );
                },
              ),
      ),
    );
  }
}
