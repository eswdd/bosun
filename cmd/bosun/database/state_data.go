package database

import (
	"encoding/json"
	"fmt"
	"time"

	"bosun.org/_third_party/github.com/garyburd/redigo/redis"
	"bosun.org/collect"
	"bosun.org/models"
	"bosun.org/opentsdb"
)

/*

lastTouched: Hash of alert key to last touched time stamp
incidentById:{id} json encoded state

openIncidents: Hash of alert key to incident id (to avoid duplicates)
incidents:{ak}: List of incidents for alert key

*/

const (
	statesLastTouchedKey   = "lastTouched"
	statesOpenIncidentsKey = "openIncidents"
)

func incidentStateKey(id int64) string {
	return fmt.Sprintf("incidentById:%d", id)
}

func incidentsForAlertKeyKey(ak models.AlertKey) string {
	return fmt.Sprintf("incidents:%s", ak)
}

type StateDataAccess interface {
	TouchAlertKey(ak models.AlertKey, t time.Time) error

	GetOpenIncident(ak models.AlertKey) (*models.IncidentState, error)
	GetIncidentState(incidentId int64) (*models.IncidentState, error)
	UpdateIncidentState(s *models.IncidentState) error
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
	state := &models.IncidentState{}
	if err = json.Unmarshal(b, state); err != nil {
		return nil, err
	}
	return state, nil
}

func (d *dataAccess) UpdateIncidentState(s *models.IncidentState) error {
	defer collect.StartTimer("redis", opentsdb.TagSet{"op": "UpdateIncident"})()
	conn := d.GetConnection()
	defer conn.Close()

	//if id is still zero, assign new id.
	if s.Id == 0 {
		id, err := redis.Int64(conn.Do("INCR", "maxIncidentId"))
		if err != nil {
			return err
		}
		s.Id = id
		_, err = conn.Do("LPUSH", incidentsForAlertKeyKey(s.AlertKey), s.Id)
		if err != nil {
			return err
		}
	}

	var err error
	if s.Open {
		_, err = conn.Do("HSET", statesOpenIncidentsKey, s.AlertKey, s.Id)
	} else {
		_, err = conn.Do("HDEL", statesOpenIncidentsKey, s.AlertKey)
	}
	if err != nil {
		return err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = conn.Do("SET", incidentStateKey(s.Id), data)
	return err
}
