package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	defaultPasswordLength = 32
	minPasswordLength     = 8
	apiKeyLength          = 64
)

// GenerateSecurePassword generates a strong password with mixed character sets
func GenerateSecurePassword(length int, includeSymbols bool) (string, error) {
	if length < minPasswordLength {
		length = minPasswordLength
	}

	lower := "abcdefghjkmnpqrstuvwxyz"
	upper := "ABCDEFGHJKMNPQRSTUVWXYZ"
	digits := "23456789" // Avoid confusing 0/1 with O/I
	symbols := "!@#$%^&*"

	allChars := lower + upper + digits
	if includeSymbols {
		allChars += symbols
	}

	buf := make([]byte, length)

	// pick selects a random byte from set, propagating any RNG error.
	pick := func(set string) (byte, error) {
		idx, err := randInt(len(set))
		if err != nil {
			return 0, err
		}
		return set[idx], nil
	}

	var err error
	// Ensure at least one of each required type
	if buf[0], err = pick(lower); err != nil {
		return "", err
	}
	if buf[1], err = pick(upper); err != nil {
		return "", err
	}
	if buf[2], err = pick(digits); err != nil {
		return "", err
	}
	nextIdx := 3

	if includeSymbols {
		if buf[3], err = pick(symbols); err != nil {
			return "", err
		}
		nextIdx = 4
	}

	// Fill the rest randomly
	for i := nextIdx; i < length; i++ {
		if buf[i], err = pick(allChars); err != nil {
			return "", err
		}
	}

	// Shuffle the result
	perm, err := randPerm(length)
	if err != nil {
		return "", err
	}

	shuffled := make([]byte, length)
	for i, idx := range perm {
		shuffled[i] = buf[idx]
	}

	return string(shuffled), nil
}

// GenerateAPIKey generates a hex-encoded random API key
func GenerateAPIKey(length int) (string, error) {
	bytes := make([]byte, length/2) // 2 hex chars per byte
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateBase64Key generates a base64 encoded strong random key
func GenerateBase64Key(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// GenerateHtpasswd produces an htpasswd-compatible line of the form
// "<username>:<bcrypt(password)>". Harbor's registry container mounts a
// secret key whose value is exactly this format and uses it as a basic-auth
// credentials file at /etc/registry/passwd. The bcrypt cost matches the
// htpasswd(1) default (10).
func GenerateHtpasswd(username, password string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("htpasswd: username is required")
	}
	if password == "" {
		return "", fmt.Errorf("htpasswd: password is required")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", fmt.Errorf("htpasswd: bcrypt: %w", err)
	}
	return fmt.Sprintf("%s:%s", username, string(hashed)), nil
}

// GeneratePassphrase generates a word-based passphrase. Returns an error if
// the secure RNG fails (rather than panicking), so callers can surface it like
// every other generator.
func GeneratePassphrase(wordCount int, separator string) (string, error) {
	words := []string{
		"abbey", "acorn", "active", "adrift", "agate", "alarm", "album", "aloft",
		"alpen", "amber", "ample", "anchor", "anvil", "apple", "apron", "arbor",
		"arctic", "ardent", "arena", "argon", "arrow", "aster", "atlas", "attic",
		"audio", "augur", "avid", "azure", "babel", "badge", "banjo", "barge",
		"baron", "basil", "baton", "bayou", "beech", "bevel", "birch", "bison",
		"blaze", "bloom", "bluff", "blunt", "bongo", "boon", "borax", "botanic",
		"brace", "braid", "bravo", "briar", "brine", "brisk", "broil", "brook",
		"brush", "brute", "bugle", "bumpy", "buoyant", "cadet", "calyx", "cameo",
		"canal", "canoe", "caper", "cargo", "carve", "cedar", "cellar", "chalk",
		"charm", "chart", "chase", "cheek", "chess", "chest", "chief", "chime",
		"chip", "chisel", "chord", "civic", "clair", "clamp", "claret", "clasp",
		"clave", "cleft", "clerk", "cliff", "cloak", "cobalt", "comet", "comic",
		"coral", "cordon", "crest", "crisp", "crown", "crypt", "cubic", "cumin",
		"curve", "cyber", "cycle", "dagga", "daring", "datum", "daunt", "debut",
		"decoy", "delta", "depot", "derby", "depth", "detour", "digit", "diode",
		"disco", "divan", "diver", "divot", "dizzy", "dock", "dogma", "dolmen",
		"donor", "dopy", "dorsal", "doric", "dowel", "draft", "drama", "drape",
		"drift", "druid", "duple", "dural", "dusky", "dwarf", "easel", "edict",
		"eight", "elder", "elegy", "elite", "elver", "ember", "emery", "epoch",
		"equip", "ergot", "ethos", "evoke", "exact", "exalt", "facet", "faint",
		"falco", "farse", "feast", "femur", "fence", "feral", "ferry", "fetch",
		"fiber", "fiery", "fifth", "finch", "fjord", "flare", "flask", "flair",
		"flint", "flora", "fluent", "flume", "focus", "foggy", "folio", "forum",
		"frond", "frost", "frugal", "fudge", "fungi", "furlong", "gadget", "gable",
		"gamma", "garble", "garnet", "gaunt", "gavel", "gecko", "genic", "geyser",
		"girth", "gizmo", "glade", "gleam", "glide", "globe", "gloom", "gloss",
		"glyph", "gnarled", "gnash", "gnome", "gouge", "gourd", "grade", "grand",
		"grape", "grasp", "gravel", "graze", "groan", "grotto", "grove", "gruel",
		"guild", "guile", "gusto", "gypsy", "halve", "hatch", "hazel", "heist",
		"helms", "heron", "hinge", "hippo", "holly", "homer", "horde", "hornet",
		"humus", "hyena", "hymn", "ichor", "image", "imply", "incur", "index",
		"indie", "inert", "infer", "inlet", "intel", "ionic", "irate", "ivory",
		"jaunt", "jetty", "jewel", "joust", "judge", "jumbo", "karma", "kelp",
		"knave", "knell", "knoll", "kudos", "lance", "lapel", "larva", "laser",
		"latch", "latte", "lava", "ledge", "lever", "liege", "light", "lilac",
		"limbo", "linen", "lingo", "lipid", "lissome", "lithe", "llano", "lodge",
		"logic", "lofty", "lucid", "lunar", "lunge", "lusty", "lyric", "macaw",
		"maize", "major", "manor", "maple", "march", "marsh", "maxim", "melee",
		"metro", "micro", "might", "mirth", "mitre", "mixer", "mocha", "model",
		"module", "moose", "morph", "mossy", "motto", "mural", "myrrh", "nadir",
		"naive", "navel", "niche", "nomad", "notch", "novel", "nurse", "nymph",
		"oaken", "oasis", "oblong", "octet", "olive", "onset", "optic", "orbit",
		"otter", "outrun", "ovoid", "oxide", "ozone", "pagan", "parcel", "parse",
		"patch", "pause", "pearl", "pedal", "penny", "perch", "peril", "petal",
		"phase", "pilot", "pixel", "pivot", "pixel", "plaid", "plain", "plank",
		"plasm", "plaza", "plead", "plumb", "plume", "plunge", "plunk", "polar",
		"porch", "primo", "prism", "privy", "prize", "probe", "prone", "prune",
		"psalm", "pulse", "punch", "pupil", "pygmy", "pyrite", "quaff", "quake",
		"qualm", "query", "quota", "quote", "quorum", "rabbi", "radar", "radix",
		"rally", "ramen", "rangy", "rapid", "raven", "rayon", "realm", "rebel",
		"rebus", "reedy", "relic", "remix", "repay", "resin", "retro", "rider",
		"rigid", "rivet", "robin", "rocky", "rogue", "roman", "roost", "rowan",
		"rubric", "ruddy", "rugby", "ruler", "runoff", "rustic", "rustle", "sabre",
		"salty", "sapphire", "scala", "scone", "scope", "score", "scout", "sedan",
		"serif", "shaft", "shale", "sheen", "shelf", "shield", "shrank", "shrub",
		"sigma", "silex", "sinew", "sisal", "sixth", "skiff", "skill", "skimp",
		"slack", "slant", "sleet", "slick", "slide", "slime", "slope", "smelt",
		"smile", "snare", "snell", "snowy", "sober", "solar", "sonic", "sooty",
		"spade", "spark", "spasm", "spawn", "spear", "speck", "spell", "spent",
		"spice", "spike", "spine", "spire", "spoil", "spore", "sport", "spout",
		"sprig", "spunk", "squad", "squid", "stack", "staff", "stain", "stale",
		"stalk", "stall", "stamp", "stand", "stark", "start", "stave", "steal",
		"steel", "steep", "steer", "stern", "still", "sting", "stock", "stoic",
		"stomp", "stony", "stork", "storm", "stout", "stove", "strap", "straw",
		"strut", "study", "stung", "stunt", "style", "suede", "suite", "sulky",
		"surge", "sushi", "swift", "synod", "table", "talon", "tango", "tapir",
		"taunt", "tavern", "tawny", "tenet", "tense", "tepid", "terra", "terse",
		"thorn", "throe", "tiara", "tidal", "tiger", "tilde", "title", "toast",
		"token", "topaz", "totem", "toxic", "trace", "track", "trade", "trail",
		"train", "tramp", "trawl", "triad", "trial", "trick", "tripe", "troop",
		"trout", "trove", "truce", "tundra", "tuner", "tunic", "tuple", "twang",
		"tweak", "tweed", "twerp", "twine", "twirl", "ultra", "undge", "union",
		"unpin", "unzip", "upend", "urbane", "usher", "utmost", "utter", "uvula",
		"valor", "valve", "vapid", "vault", "vegan", "venom", "verge", "vetch",
		"vigil", "viper", "virtu", "vista", "vivid", "vocal", "vodka", "vouch",
		"vying", "wafer", "waltz", "warty", "weald", "wedge", "weedy", "whack",
		"whale", "wharf", "wheat", "wheel", "witch", "woken", "woody", "wordy",
		"worst", "wrath", "yacht", "yearn", "yield", "yokel", "forge", "zonal",
	}

	selected := make([]string, wordCount)
	for i := range wordCount {
		idx, err := randInt(len(words))
		if err != nil {
			return "", err
		}
		selected[i] = words[idx]
	}

	return strings.Join(selected, separator), nil
}

// Helper: randInt returns a secure random integer [0, max)
func randInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randPerm(n int) ([]int, error) {
	// There is no crypto/rand.Perm, implement Fisher-Yates shuffle if strict needed
	// For simplicity, we can use a basic shuffle here or just rely on random generation filling

	// Using a slice and random swaps
	indices := make([]int, n)
	for i := 0; i < n; i++ {
		indices[i] = i
	}

	for i := n - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return nil, err
		}
		indices[i], indices[j] = indices[j], indices[i]
	}

	return indices, nil
}
