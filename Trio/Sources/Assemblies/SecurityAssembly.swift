import CryptoKit
import Foundation
import SwiftUI
import Swinject

final class SecurityAssembly: Assembly {
    func assemble(container: Container) {
        container.register(UnlockManager.self) { _ in BaseUnlockManager() }
        container.register(BolusPasswordManager.self) { _ in BaseBolusPasswordManager() }
    }
}

// ===== merged from BolusPasswordManager.swift (kept in an existing file so no Xcode project edit is needed) =====

/// Child-safety "Gate 2" for Trio.
///
/// Stores and verifies a parent-set password that is required before a **manual, user-initiated
/// pump bolus** from the main Treatments UI can be enacted. This NEVER affects the automated loop,
/// SMBs, temp basals, or any other automated dosing path — it is consulted only from
/// `Treatments.StateModel.addPumpInsulin()`.
///
/// Security properties:
/// - The plaintext password is never stored. We persist only `{salt, hash}` where
///   `hash = SHA256(salt + passwordBytes)` with a fresh random 16-byte salt per password.
/// - The credential lives in a **non-syncing** Keychain instance (`BaseKeychain(synchronizable: false)`)
///   so it never propagates via iCloud Keychain. This matters because the family shares an iCloud
///   account; a synced secret could leak to other devices.
/// - A simple, durable lockout (5 failed attempts → 5 minute cooldown) is persisted in
///   `UserDefaults` so force-quitting and relaunching the app does not reset it.
protocol BolusPasswordManager {
    /// `true` once a parent has configured a bolus password. When `false`, the manual-bolus gate
    /// must be a no-op so existing behavior is completely unchanged.
    var isBolusPasswordSet: Bool { get }

    /// Stores a new bolus password (replacing any existing one) as a salted SHA-256 hash.
    /// Setting a password also clears any active lockout / failure count.
    /// - Throws: `BolusPasswordError` if the password is empty or persistence fails.
    func setBolusPassword(_ password: String) throws

    /// Verifies a candidate password against the stored salted hash using a constant-time compare.
    /// On success the failure counter and lockout are reset. On failure the counter is incremented
    /// and a lockout may be engaged. Returns `false` (never throws) when no password is set.
    func verifyBolusPassword(_ password: String) -> Bool

    /// Removes the stored bolus password and clears lockout state. After this, the gate is disengaged.
    func clearBolusPassword()

    // MARK: - Lockout

    /// `true` while bolus-password entry is locked out due to repeated failures.
    var isLockedOut: Bool { get }

    /// Seconds remaining on the current lockout, or `0` if not locked out.
    var lockoutRemaining: TimeInterval { get }

    /// Number of consecutive failed attempts since the last success (capped for display).
    var failedAttemptCount: Int { get }

    /// Max consecutive failures before a lockout engages.
    var maxFailedAttempts: Int { get }
}

enum BolusPasswordError: Error {
    case emptyPassword
    case persistenceFailed
}

final class BaseBolusPasswordManager: BolusPasswordManager {
    /// Codable credential persisted in the Keychain. Only the salt and the derived hash are stored.
    private struct StoredCredential: Codable {
        let salt: Data
        let hash: Data
    }

    /// Lockout counters, persisted in the Keychain (NOT UserDefaults) so they survive an uninstall/
    /// reinstall — a reinstall can no longer reset the cooldown to get a fresh batch of guesses.
    private struct LockoutState: Codable {
        var failedAttempts: Int
        var lockoutUntil: TimeInterval
    }

    enum Config {
        /// Keychain key for the salted-hash credential. Versioned: bumping the suffix (v1 -> v2)
        /// orphans any previously-stored password, giving a clean "Not Set" slate on next launch.
        static let credentialKey = "trio.bolusPassword.credential.v2"
        /// Reliable, process-wide "gating is enabled" flag (UserDefaults). The gate reads this so the
        /// decision is consistent across screens and fails closed even if a Keychain read hiccups.
        static let enabledKey = "trio.bolusPassword.enabled.v2"
        /// Keychain key for the lockout state — stored in the Keychain so it shares the credential's
        /// fate and survives uninstall/reinstall (so a reinstall can't reset the lockout).
        static let lockoutKey = "trio.bolusPassword.lockout.v2"

        static let saltByteCount = 16
        static let maxFailedAttempts = 5
        static let lockoutDuration: TimeInterval = 5 * 60 // 5 minutes
    }

    /// Dedicated, NON-syncing Keychain instance. We deliberately do not reuse the DI-registered
    /// `Keychain` (which defaults to `synchronizable: true`) so this secret never syncs via iCloud.
    private let keychain: Keychain
    private let defaults: UserDefaults
    /// Serializes the lockout read-modify-write so the attempt cap stays a hard ceiling under any interleaving.
    private let lockoutLock = NSLock()

    // NOTE: uses the Keychain's default accessibility (afterFirstUnlock), NOT a *ThisDeviceOnly* level.
    // Device-binding was tried but iOS treats accessibility as part of an item's identity, so it can't
    // update a credential already stored at a different level by an earlier build → "Could not save".
    // Offline/backup-extraction hardening was de-scoped anyway; revisit later with an explicit
    // delete-then-add migration if device-binding is wanted.
    init(keychain: Keychain = BaseKeychain(synchronizable: false), defaults: UserDefaults = .standard) {
        self.keychain = keychain
        self.defaults = defaults
    }

    // MARK: - Password storage

    var isBolusPasswordSet: Bool {
        // Reliable flag first (consistent across screens); credential check as a fail-closed backstop.
        defaults.bool(forKey: Config.enabledKey) || loadCredential() != nil
    }

    func setBolusPassword(_ password: String) throws {
        guard !password.isEmpty else {
            throw BolusPasswordError.emptyPassword
        }

        var saltBytes = [UInt8](repeating: 0, count: Config.saltByteCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        guard status == errSecSuccess else {
            throw BolusPasswordError.persistenceFailed
        }
        let salt = Data(saltBytes)
        let hash = Self.hash(password: password, salt: salt)

        let credential = StoredCredential(salt: salt, hash: hash)
        // Use the Result-returning `Keychain` API (not the `KeyValueStorage` variant, which
        // asserts on failure). The explicit type annotation disambiguates the overload.
        let result: Result<Void, KeychainError> = keychain.setValue(credential, forKey: Config.credentialKey)
        guard case .success = result else {
            throw BolusPasswordError.persistenceFailed
        }

        // Mark gating enabled via a reliable, process-wide flag that the gate reads.
        defaults.set(true, forKey: Config.enabledKey)
        // A freshly set password starts from a clean slate.
        resetFailureState()
    }

    func verifyBolusPassword(_ password: String) -> Bool {
        // Enforce the lockout here too, so EVERY verify path honors it — the bolus gate and the
        // Settings change/remove screen alike — closing that second brute-force oracle.
        guard !isLockedOut else { return false }

        guard let credential = loadCredential() else {
            // No password configured → the gate is disengaged; nothing to verify.
            return false
        }

        // If a previous lockout has since expired, start the counter fresh. Otherwise the count
        // would stay pinned at the cap and the next single mistake would instantly re-lock.
        if failedAttemptCount >= Config.maxFailedAttempts {
            resetFailureState()
        }

        let candidate = Self.hash(password: password, salt: credential.salt)
        // Constant-time comparison to avoid timing side channels.
        let matches = constantTimeEquals(candidate, credential.hash)

        if matches {
            resetFailureState()
        } else {
            registerFailedAttempt()
        }
        return matches
    }

    func clearBolusPassword() {
        keychain.removeObject(forKey: Config.credentialKey)
        defaults.set(false, forKey: Config.enabledKey)
        resetFailureState()
    }

    // MARK: - Lockout

    var failedAttemptCount: Int {
        loadLockout().failedAttempts
    }

    var maxFailedAttempts: Int { Config.maxFailedAttempts }

    var isLockedOut: Bool {
        lockoutRemaining > 0
    }

    var lockoutRemaining: TimeInterval {
        let until = loadLockout().lockoutUntil
        guard until > 0 else { return 0 }
        let remaining = until - Date().timeIntervalSince1970
        return remaining > 0 ? remaining : 0
    }

    // MARK: - Private helpers

    private func loadCredential() -> StoredCredential? {
        // Explicit type annotation selects the Result-returning `Keychain.getValue` overload.
        let result: Result<StoredCredential?, KeychainError> = keychain.getValue(
            StoredCredential.self,
            forKey: Config.credentialKey
        )
        if case let .success(value) = result {
            return value
        }
        return nil
    }

    private static func hash(password: String, salt: Data) -> Data {
        var data = salt
        data.append(Data(password.utf8))
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    private func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (l, r) in zip(lhs, rhs) {
            difference |= l ^ r
        }
        return difference == 0
    }

    private func loadLockout() -> LockoutState {
        let result: Result<LockoutState?, KeychainError> = keychain.getValue(LockoutState.self, forKey: Config.lockoutKey)
        if case let .success(value) = result, let value = value {
            return value
        }
        return LockoutState(failedAttempts: 0, lockoutUntil: 0)
    }

    private func registerFailedAttempt() {
        lockoutLock.lock()
        defer { lockoutLock.unlock() }
        var state = loadLockout()
        state.failedAttempts += 1
        if state.failedAttempts >= Config.maxFailedAttempts {
            state.lockoutUntil = Date().addingTimeInterval(Config.lockoutDuration).timeIntervalSince1970
        }
        // A write failure here leaves the prior (more-locked) state in place — i.e. fails closed.
        let _: Result<Void, KeychainError> = keychain.setValue(state, forKey: Config.lockoutKey)
    }

    private func resetFailureState() {
        lockoutLock.lock()
        defer { lockoutLock.unlock() }
        keychain.removeObject(forKey: Config.lockoutKey)
    }
}

// ===== merged from SecurityDataFlow.swift (kept in an existing file so no Xcode project edit is needed) =====
enum Security {
    enum Config {}
}

protocol SecurityProvider: Provider {}

// ===== merged from SecurityProvider.swift (kept in an existing file so no Xcode project edit is needed) =====
extension Security {
    final class Provider: BaseProvider, SecurityProvider {}
}

// ===== merged from SecurityStateModel.swift (kept in an existing file so no Xcode project edit is needed) =====

extension Security {
    final class StateModel: BaseStateModel<Provider> {
        @Injected() var bolusPasswordManager: BolusPasswordManager!

        /// Mirrors `bolusPasswordManager.isBolusPasswordSet` so the View can react to changes.
        @Published var isBolusPasswordSet: Bool = false

        /// Minimum length we require for a bolus password. Kept intentionally small (kids/parents
        /// need to type it quickly) while still discouraging trivial single-character secrets.
        let minimumPasswordLength = 4

        override func subscribe() {
            isBolusPasswordSet = bolusPasswordManager.isBolusPasswordSet
        }

        /// Sets or replaces the bolus password. Returns an error message on failure, or `nil` on success.
        @discardableResult func setPassword(_ password: String) -> String? {
            guard password.count >= minimumPasswordLength else {
                return String(localized: "Password must be at least \(minimumPasswordLength) characters.")
            }
            do {
                try bolusPasswordManager.setBolusPassword(password)
                isBolusPasswordSet = bolusPasswordManager.isBolusPasswordSet
                return nil
            } catch BolusPasswordError.emptyPassword {
                return String(localized: "Password cannot be empty.")
            } catch {
                return String(localized: "Could not save the password. Please try again.")
            }
        }

        /// Removes the bolus password. Requires the current password to be verified first.
        /// Returns an error message on failure, or `nil` on success.
        @discardableResult func removePassword(currentPassword: String) -> String? {
            guard bolusPasswordManager.verifyBolusPassword(currentPassword) else {
                return String(localized: "Incorrect current password.")
            }
            bolusPasswordManager.clearBolusPassword()
            isBolusPasswordSet = bolusPasswordManager.isBolusPasswordSet
            return nil
        }

        /// Verifies the current password (used before allowing a change). Returns `true` if correct.
        func verifyCurrentPassword(_ password: String) -> Bool {
            bolusPasswordManager.verifyBolusPassword(password)
        }
    }
}

// ===== merged from SecurityRootView.swift (kept in an existing file so no Xcode project edit is needed) =====

extension Security {
    struct RootView: BaseView {
        let resolver: Resolver

        @StateObject var state = StateModel()

        @State private var newPassword: String = ""
        @State private var confirmPassword: String = ""
        @State private var currentPassword: String = ""
        @State private var feedbackMessage: String?
        @State private var feedbackIsError: Bool = true

        @Environment(\.colorScheme) var colorScheme
        @Environment(AppState.self) var appState

        var body: some View {
            List {
                Section(
                    header: Text("Bolus Password"),
                    content: {
                        Text(
                            "Require a password before a manual bolus can be given from the Treatments screen. This does not affect automated insulin delivery (the loop), SMBs, or carb logging."
                        )
                        .font(.footnote)
                        .foregroundColor(.secondary)

                        HStack {
                            Text("Status")
                            Spacer()
                            Text(state.isBolusPasswordSet ? "Enabled" : "Not Set")
                                .foregroundColor(state.isBolusPasswordSet ? .green : .secondary)
                        }
                    }
                ).listRowBackground(Color.chart)

                if !state.isBolusPasswordSet {
                    setPasswordSection
                } else {
                    changePasswordSection
                    removePasswordSection
                }

                if let feedbackMessage = feedbackMessage {
                    Section {
                        Text(feedbackMessage)
                            .font(.footnote)
                            .foregroundColor(feedbackIsError ? .red : .green)
                    }.listRowBackground(Color.chart)
                }
            }
            .listSectionSpacing(sectionSpacing)
            .scrollContentBackground(.hidden)
            .background(appState.trioBackgroundColor(for: colorScheme))
            .onAppear(perform: configureView)
            .navigationBarTitle("Security")
            .navigationBarTitleDisplayMode(.automatic)
        }

        // MARK: - Set (no password yet)

        private var setPasswordSection: some View {
            Section(
                header: Text("Set Password"),
                content: {
                    SecureField(String(localized: "New password"), text: $newPassword)
                        .textContentType(.oneTimeCode)
                        .autocorrectionDisabled()
                    SecureField(String(localized: "Confirm password"), text: $confirmPassword)
                        .textContentType(.oneTimeCode)
                        .autocorrectionDisabled()

                    Button("Set Password") {
                        setPasswordTapped()
                    }
                    .disabled(newPassword.isEmpty || confirmPassword.isEmpty)
                }
            ).listRowBackground(Color.chart)
        }

        // MARK: - Change (password exists)

        private var changePasswordSection: some View {
            Section(
                header: Text("Change Password"),
                content: {
                    SecureField(String(localized: "Current password"), text: $currentPassword)
                        .textContentType(.oneTimeCode)
                        .autocorrectionDisabled()
                    SecureField(String(localized: "New password"), text: $newPassword)
                        .textContentType(.oneTimeCode)
                        .autocorrectionDisabled()
                    SecureField(String(localized: "Confirm new password"), text: $confirmPassword)
                        .textContentType(.oneTimeCode)
                        .autocorrectionDisabled()

                    Button("Change Password") {
                        changePasswordTapped()
                    }
                    .disabled(currentPassword.isEmpty || newPassword.isEmpty || confirmPassword.isEmpty)
                }
            ).listRowBackground(Color.chart)
        }

        // MARK: - Remove (password exists)

        private var removePasswordSection: some View {
            Section(
                header: Text("Remove Password"),
                content: {
                    SecureField(String(localized: "Current password"), text: $currentPassword)
                        .textContentType(.oneTimeCode)
                        .autocorrectionDisabled()
                    Button("Remove Password", role: .destructive) {
                        removePasswordTapped()
                    }
                    .disabled(currentPassword.isEmpty)
                }
            ).listRowBackground(Color.chart)
        }

        // MARK: - Actions

        private func setPasswordTapped() {
            guard newPassword == confirmPassword else {
                showFeedback(String(localized: "Passwords do not match."), isError: true)
                return
            }
            if let error = state.setPassword(newPassword) {
                showFeedback(error, isError: true)
            } else {
                clearFields()
                showFeedback(String(localized: "Bolus password set."), isError: false)
            }
        }

        private func changePasswordTapped() {
            guard state.verifyCurrentPassword(currentPassword) else {
                showFeedback(String(localized: "Incorrect current password."), isError: true)
                return
            }
            guard newPassword == confirmPassword else {
                showFeedback(String(localized: "Passwords do not match."), isError: true)
                return
            }
            if let error = state.setPassword(newPassword) {
                showFeedback(error, isError: true)
            } else {
                clearFields()
                showFeedback(String(localized: "Bolus password changed."), isError: false)
            }
        }

        private func removePasswordTapped() {
            if let error = state.removePassword(currentPassword: currentPassword) {
                showFeedback(error, isError: true)
            } else {
                clearFields()
                showFeedback(String(localized: "Bolus password removed."), isError: false)
            }
        }

        private func showFeedback(_ message: String, isError: Bool) {
            feedbackMessage = message
            feedbackIsError = isError
        }

        private func clearFields() {
            newPassword = ""
            confirmPassword = ""
            currentPassword = ""
        }
    }
}
