package harness

import "testing"

func TestJudgeKey(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		probe string
		want  keyVerdict
	}{
		{
			name:  "the renderer drew frames and nothing was recorded: the browser dropped it",
			key:   "End",
			probe: `{"keys":[],"frames":312,"hasFocus":true,"visibilityState":"visible"}`,
			want:  keyDropped,
		},
		{
			name:  "the key arrived: a page that ignores it still fails later, not here",
			key:   "End",
			probe: `{"keys":["End"],"frames":312,"hasFocus":true,"visibilityState":"visible"}`,
			want:  keyArrived,
		},
		{
			name:  "another key arrived: it does not stand for this one",
			key:   "End",
			probe: `{"keys":["Home"],"frames":312,"hasFocus":true,"visibilityState":"visible"}`,
			want:  keyDropped,
		},
		{
			name:  "Space is recorded as a space",
			key:   "Space",
			probe: `{"keys":[" "],"frames":312,"hasFocus":true,"visibilityState":"visible"}`,
			want:  keyArrived,
		},
		{
			name:  "focus is not required: most parallel Chromes do not have it",
			key:   "t",
			probe: `{"keys":[],"frames":312,"hasFocus":false,"visibilityState":"visible"}`,
			want:  keyDropped,
		},
		{
			name:  "the recorder drew no frames (@nojs): an empty recorder proves nothing",
			key:   "t",
			probe: `{"keys":[],"frames":0,"hasFocus":true,"visibilityState":"visible"}`,
			want:  keyUnconfirmable,
		},
		{
			name:  "no recorder at all",
			key:   "t",
			probe: `{"keys":null,"frames":null,"hasFocus":true,"visibilityState":"visible"}`,
			want:  keyUnconfirmable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := parseKeyProbe(tc.probe)
			if err != nil {
				t.Fatal(err)
			}
			if got := judgeKey(probe, tc.key); got != tc.want {
				t.Errorf("judgeKey(%s, %q) = %v, want %v", tc.probe, tc.key, got, tc.want)
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
