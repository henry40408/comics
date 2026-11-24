package harness

import "testing"

func TestKeyNeverArrived(t *testing.T) {
	cases := []struct {
		name  string
		probe string
		want  bool
	}{
		{
			name:  "the renderer drew frames and nothing was recorded: the browser dropped it",
			probe: `{"keys":[],"frames":312,"hasFocus":true,"visibilityState":"visible"}`,
			want:  true,
		},
		{
			name:  "a key arrived: the page ignored it",
			probe: `{"keys":["End"],"frames":312,"hasFocus":true,"visibilityState":"visible"}`,
			want:  false,
		},
		{
			name:  "focus is not required: most parallel Chromes do not have it",
			probe: `{"keys":[],"frames":312,"hasFocus":false,"visibilityState":"visible"}`,
			want:  true,
		},
		{
			name:  "the recorder drew no frames (@nojs): an empty recorder proves nothing",
			probe: `{"keys":[],"frames":0,"hasFocus":true,"visibilityState":"visible"}`,
			want:  false,
		},
		{
			name:  "no recorder at all",
			probe: `{"keys":null,"frames":null,"hasFocus":true,"visibilityState":"visible"}`,
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := parseKeyProbe(tc.probe)
			if err != nil {
				t.Fatal(err)
			}
			if got := keyNeverArrived(probe); got != tc.want {
				t.Errorf("keyNeverArrived(%s) = %v, want %v", tc.probe, got, tc.want)
			}
		})
	}
}

func TestParseKeyProbeRejectsGarbage(t *testing.T) {
	if _, err := parseKeyProbe("not json"); err == nil {
		t.Fatal("garbage was parsed as a probe")
	}
}

// The step text says Space; a keydown handler reads " ".
func TestDomKeyIsWhatTheBrowserReports(t *testing.T) {
	for key, want := range map[string]string{
		"Space": " ", "End": "End", "Home": "Home", "ArrowLeft": "ArrowLeft", "t": "t", "m": "m",
	} {
		if got := domKey(key); got != want {
			t.Errorf("domKey(%q) = %q, want %q", key, got, want)
		}
	}
}
