package database

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	"bosun.org/_third_party/github.com/garyburd/redigo/redis"
	"bosun.org/collect"
	"bosun.org/models"
	"bosun.org/opentsdb"
)

/*

lastTouched: Hash of alert key to last touched time stamp
incidentStates: Hash of incidentId to gob encoded state

openIncidents: Hash of alert key to incident id (to avoid duplicates)
incidentState:{ak}: List of incidents for alert key

*/

const (
	statesLastTouchedKey   = "lastTouched"
	statesOpenIncidentsKey = "openIncidents"
)

func incidentStateKey(id int64) string {
	return fmt.Sprintf("incidentState:%d", id)
}

type StateDataAccess interface {
	TouchAlertKey(ak models.AlertKey, t time.Time) error

	GetOpenIncident(ak models.AlertKey) (*models.IncidentState, error)
	GetIncidentState(incidentId int64) (*models.IncidentState, error)
	UpdateIncidentState(incidentId int64, s *models.IncidentState) error
}

func (d *dataAccess) State() StateDataAccess {
	return d
}

func (d *dataAccess) TouchAlertKey(ak models.AlertKey, t time.Time) error {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "TouchAlertKey"})()
	conn := d.GetConnection()
	defer conn.Close()

	_, err := conn.Do("HSET", statesLastTouchedKey, string(ak), t.UTC().Unix())
	return err
}

func (d *dataAccess) GetOpenIncident(ak models.AlertKey) (*models.IncidentState, error) {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "GetOpenIncident"})()
	conn := d.GetConnection()
	defer conn.Close()

	id, err := redis.Int64(conn.Do("HGET", statesOpenIncidentsKey, string(ak)))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}
	return d.GetIncidentState(id)

}
func (d *dataAccess) GetIncidentState(incidentId int64) (*models.IncidentState, error) {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "GetIncident"})()
	conn := d.GetConnection()
	defer conn.Close()

	b, err := redis.Bytes(conn.Do("GET", incidentStateKey(incidentId)))
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(b)
	dec := gob.NewDecoder(r)
	state := &models.IncidentState{}
	if err = dec.Decode(state); err != nil {
		return nil, err
	}
	return state, nil
}

func (d *dataAccess) UpdateIncidentState(incidentId int64, s *models.IncidentState) error {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "UpdateIncident"})()
	conn := d.GetConnection()
	defer conn.Close()

	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	err := enc.Encode(s)
	if err != nil {
		fmt.Println("!!!", err)
		return err
	}
	fmt.Println("UPDATE!!")
	_, err = conn.Do("SET", incidentStateKey(incidentId), buf.Bytes())
	return err
}
