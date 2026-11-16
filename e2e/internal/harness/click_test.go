package harness

import "testing"

func TestInputNeverArrived(t *testing.T) {
	cases := []struct {
		name  string
		probe string
		want  bool
	}{
		{
			name:  "aimed at the element and nothing recorded: the browser dropped it",
			probe: `{"hitIsTarget":true,"events":[],"frames":312}`,
			want:  true,
		},
		{
			name:  "aimed at the element, recorder never ran (@nojs): accepted on hitIsTarget alone",
			probe: `{"hitIsTarget":true,"events":null,"frames":null}`,
			want:  true,
		},
		{
			name:  "events arrived: the page ignored them",
			probe: `{"hitIsTarget":true,"events":["mousedown:a#x@1,2","mouseup:a#x@1,2","click:a#x@1,2"]}`,
			want:  false,
		},
		{
			name:  "something covers the element: a page bug",
			probe: `{"hitIsTarget":false,"events":[]}`,
			want:  false,
		},
		{
			name:  "the element is gone from the document",
			probe: `{"connected":false}`,
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := parseProbe([]byte(tc.probe))
			if err != nil {
				t.Fatal(err)
			}
			if got := inputNeverArrived(probe); got != tc.want {
				t.Errorf("inputNeverArrived(%s) = %v, want %v", tc.probe, got, tc.want)
			}
		})
	}
}
